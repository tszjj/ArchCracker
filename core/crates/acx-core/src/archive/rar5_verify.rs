// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

//! RAR5 password-check verifier.
//!
//! This is an independent Rust implementation informed by the public RAR5
//! format documentation, public third-party format notes, and black-box
//! differential checks against a local `Rar.exe` fixture. The official RAR5
//! technote does not publish the full check-value derivation (it refers to
//! UnRAR source); no UnRAR source was copied or linked here, and this is not a
//! formal clean-room/legal conclusion. Release/legal sign-off is still needed.
//!
//! It only derives the password check value and returns "definitely wrong" or
//! "may be correct". A possible hit is still confirmed by the external
//! `UnRAR.exe t` oracle. It never decrypts or extracts archive data and never
//! links UnRAR code.
//!
//! Only ASCII candidates are fast-rejected. Non-ASCII RAR password encoding is
//! deliberately left to the external oracle until differential tests cover it.

use super::info::ArchiveFormat;
use super::source::ArchiveSource;
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom};

const RAR5_SIGNATURE: &[u8; 8] = b"Rar!\x1a\x07\x01\x00";
const MAX_HEADER_BYTES: u64 = 2 * 1024 * 1024;
const MAX_KDF_LOG2: u8 = 24;

/// Parsed RAR5 password check value from a header encryption or file
/// encryption record.
#[derive(Debug, Clone)]
pub struct Rar5Verifier {
    kdf_count: u8,
    salt: [u8; 16],
    check: [u8; 12],
}

impl Rar5Verifier {
    /// Parse the first encrypted record from a RAR5 archive.
    ///
    /// Returns `None` when the archive is not RAR5, has no check value, has an
    /// unknown/implausible structure, or is damaged. Any `None` means "fall
    /// back to the external oracle", never "wrong password".
    pub fn from_source(source: &ArchiveSource) -> Option<Self> {
        if source.format != ArchiveFormat::Rar5 {
            return None;
        }
        let mut reader = source.reader().ok()?;
        let mut signature = [0u8; 8];
        reader.read_exact(&mut signature).ok()?;
        if &signature != RAR5_SIGNATURE {
            return None;
        }

        let mut headers = 0usize;
        loop {
            headers += 1;
            if headers > 100_000 {
                return None;
            }

            let mut crc_bytes = [0u8; 4];
            match reader.read_exact(&mut crc_bytes) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return None,
                Err(_) => return None,
            }
            let expected_crc = u32::from_le_bytes(crc_bytes);
            let (header_size, size_bytes) = read_vint_with_bytes(&mut reader).ok()?;
            if header_size == 0 || header_size > MAX_HEADER_BYTES {
                return None;
            }
            let mut data = vec![0u8; usize::try_from(header_size).ok()?];
            reader.read_exact(&mut data).ok()?;

            let mut crc = crc32fast::Hasher::new();
            crc.update(&size_bytes);
            crc.update(&data);
            if crc.finalize() != expected_crc {
                return None;
            }

            let mut cursor = 0usize;
            let header_type = read_vint(&data, &mut cursor)?;
            let header_flags = read_vint(&data, &mut cursor)?;
            let extra_size = if header_flags & 0x0001 != 0 {
                read_vint(&data, &mut cursor)?
            } else {
                0
            };
            let data_size = if header_flags & 0x0002 != 0 {
                read_vint(&data, &mut cursor)?
            } else {
                0
            };

            match header_type {
                4 => {
                    // Archive encryption header: check value without an IV.
                    return parse_crypt_record(&data[cursor..], false).map(
                        |(kdf_count, salt, check)| Self {
                            kdf_count,
                            salt,
                            check,
                        },
                    );
                }
                2 | 3 => {
                    if extra_size > data.len() as u64 {
                        return None;
                    }
                    let extra_start = data.len() - usize::try_from(extra_size).ok()?;
                    if let Some((kdf_count, salt, check)) = parse_file_extra(&data, extra_start) {
                        return Some(Self {
                            kdf_count,
                            salt,
                            check,
                        });
                    }
                }
                5 => return None,
                _ => {}
            }

            if data_size > i64::MAX as u64 {
                return None;
            }
            if data_size > 0 && reader.seek(SeekFrom::Current(data_size as i64)).is_err() {
                return None;
            }
        }
    }

    /// Returns `Some(false)` only when the check value proves the candidate is
    /// wrong; `Some(true)` means a possible hit and must be confirmed by the
    /// external engine; `None` means the fast verifier is unavailable.
    pub fn verify(&self, password: &[u8]) -> Option<bool> {
        if self.kdf_count > MAX_KDF_LOG2 || !password.is_ascii() {
            return None;
        }
        // Verify the 4-byte checksum of the stored 8-byte password check first.
        let digest = Sha256::digest(&self.check[..8]);
        if digest[..4] != self.check[8..] {
            return None;
        }

        let iterations = 1u32.checked_shl(u32::from(self.kdf_count))?;
        let check_source = pbkdf2_block_sha256(password, &self.salt, iterations + 32);
        let mut derived = [0u8; 8];
        for (index, byte) in check_source.iter().copied().enumerate() {
            derived[index % derived.len()] ^= byte;
        }
        Some(derived == self.check[..8])
    }
}

fn parse_file_extra(data: &[u8], start: usize) -> Option<(u8, [u8; 16], [u8; 12])> {
    let mut cursor = start;
    while cursor < data.len() {
        let record_start = cursor;
        let size = usize::try_from(read_vint(data, &mut cursor)?).ok()?;
        if size == 0 {
            return None;
        }
        let type_start = cursor;
        let record_type = read_vint(data, &mut cursor)?;
        let record_end = type_start.checked_add(size)?;
        if record_end > data.len() {
            return None;
        }
        if record_type == 1 {
            return parse_crypt_record(&data[cursor..record_end], true);
        }
        cursor = record_end;
        if cursor <= record_start {
            return None;
        }
    }
    None
}

/// Parse the body of an encryption record.
///
/// `has_iv` is true for file encryption records; archive header encryption
/// records store no IV.
fn parse_crypt_record(body: &[u8], has_iv: bool) -> Option<(u8, [u8; 16], [u8; 12])> {
    let mut cursor = 0usize;
    let version = read_vint(body, &mut cursor)?;
    if version != 0 {
        return None;
    }
    let flags = read_vint(body, &mut cursor)?;
    if flags & 0x0001 == 0 {
        return None;
    }
    let kdf_count = *body.get(cursor)?;
    cursor += 1;
    let salt = body.get(cursor..cursor + 16)?.try_into().ok()?;
    cursor += 16;
    if has_iv {
        cursor += 16;
    }
    let check = body.get(cursor..cursor + 12)?.try_into().ok()?;
    Some((kdf_count, salt, check))
}

fn read_vint(data: &[u8], cursor: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    let mut shift = 0u32;
    loop {
        let byte = *data.get(*cursor)?;
        *cursor += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
}

fn read_vint_with_bytes<R: Read>(reader: &mut R) -> std::io::Result<(u64, Vec<u8>)> {
    let mut bytes = Vec::with_capacity(4);
    let mut value = 0u64;
    let mut shift = 0u32;
    loop {
        let mut byte = [0u8; 1];
        reader.read_exact(&mut byte)?;
        bytes.push(byte[0]);
        value |= u64::from(byte[0] & 0x7f) << shift;
        if byte[0] & 0x80 == 0 {
            return Ok((value, bytes));
        }
        shift += 7;
        if shift > 63 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "RAR5 vint is too long",
            ));
        }
    }
}

/// One 32-byte PBKDF2-HMAC-SHA256 block (block index 1).
///
/// RAR5 only needs block 1 for its check value. Keeping the HMAC/PBKDF2 loop
/// local avoids a second crypto dependency and lets the release build use the
/// same SHA-256 backend as the rest of the core.
fn pbkdf2_block_sha256(password: &[u8], salt: &[u8; 16], iterations: u32) -> [u8; 32] {
    let mut salt_block = [0u8; 20];
    salt_block[..16].copy_from_slice(salt);
    salt_block[19] = 1;

    let mut u = hmac_sha256(password, &salt_block);
    let mut result = u;
    for _ in 1..iterations {
        u = hmac_sha256(password, &u);
        for (result_byte, u_byte) in result.iter_mut().zip(u.iter()) {
            *result_byte ^= *u_byte;
        }
    }
    result
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut block = [0u8; 64];
    if key.len() > block.len() {
        let digest = Sha256::digest(key);
        block[..digest.len()].copy_from_slice(&digest);
    } else {
        block[..key.len()].copy_from_slice(key);
    }

    let mut inner_pad = block;
    let mut outer_pad = block;
    for byte in &mut inner_pad {
        *byte ^= 0x36;
    }
    for byte in &mut outer_pad {
        *byte ^= 0x5c;
    }

    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(data);
    let inner = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner);
    outer.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn known_verifier() -> Rar5Verifier {
        Rar5Verifier {
            kdf_count: 15,
            salt: [
                0x82, 0x46, 0xbf, 0x4a, 0x50, 0xc8, 0x06, 0x74, 0x18, 0x97, 0x74, 0x19, 0x6e, 0x05,
                0x51, 0xb3,
            ],
            check: [
                0xc0, 0xfa, 0x75, 0x86, 0xaf, 0xb0, 0xc2, 0x4c, 0xe4, 0xcd, 0x6f, 0xd5,
            ],
        }
    }

    #[test]
    fn known_check_value_accepts_only_the_right_password() {
        let verifier = known_verifier();
        assert_eq!(verifier.verify(b"U0b7258526OROQY"), Some(true));
        assert_eq!(verifier.verify(b"wrong_password"), Some(false));
    }

    #[test]
    fn non_ascii_falls_back_to_external_oracle() {
        assert_eq!(known_verifier().verify("密码".as_bytes()), None);
    }

    #[test]
    fn corrupt_check_checksum_falls_back() {
        let mut verifier = known_verifier();
        verifier.check[8] ^= 0xff;
        assert_eq!(verifier.verify(b"U0b7258526OROQY"), None);
    }
}
