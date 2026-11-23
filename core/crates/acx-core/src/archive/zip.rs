// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

//! ZIP engine: metadata preflight plus ZipCrypto candidate verification (W1).
//!
//! The W1 slice only supports the legacy ZipCrypto scheme. AES-encrypted
//! entries are detected during preflight and reported as [`Encryption::Aes`],
//! but the crate is built without the `aes-crypto` feature, so verifying an
//! AES candidate returns [`AcxError::Unsupported`] instead of a guessed
//! verdict.

use super::info::{ArchiveFormat, ArchiveInfo, Encryption, EntryInfo, PasswordTest};
use super::{ArchiveSession, ArchiveSessionFactory};
use crate::error::{AcxError, Result};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use zip::result::ZipError;
use zip::ZipArchive;

/// Hard cap for one verification pass during the W1 slice. The W1 corpus is
/// tiny; refusing huge entries keeps a dictionary attack from turning into an
/// accidental full-file decompression.
const MAX_VERIFY_BYTES: u64 = 64 * 1024 * 1024;

/// Header id of the WinZip AES extra field (APPNOTE 4.5.14).
const AES_EXTRA_FIELD_ID: u16 = 0x9901;

/// One open ZIP archive, owned by a scheduler worker.
pub struct ZipSession {
    archive: ZipArchive<File>,
    info: ArchiveInfo,
}

impl ZipSession {
    /// Open `path` and record the metadata the scheduler needs.
    ///
    /// Entries are inspected with [`ZipArchive::by_index_raw`] so that opening
    /// an encrypted archive never requires the password. An archive without
    /// entries is rejected with [`AcxError::EmptyArchive`]; an archive without
    /// encrypted entries is *not* an error (callers decide what to do).
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path)?;
        let mut archive = ZipArchive::new(file)?;
        if archive.is_empty() {
            return Err(AcxError::EmptyArchive);
        }

        let mut entries = Vec::with_capacity(archive.len());
        // (uncompressed size, index, encryption) of the smallest encrypted file.
        let mut selected: Option<(u64, usize, Encryption)> = None;
        let mut has_encrypted_file = false;

        for index in 0..archive.len() {
            let entry = archive.by_index_raw(index)?;

            let encryption = if !entry.encrypted() {
                Encryption::None
            } else if has_aes_extra_field(entry.extra_data().as_deref()) {
                Encryption::Aes
            } else {
                Encryption::ZipCrypto
            };

            // `name()` decodes per the archive's encoding flag. Fall back to a
            // lossy view of the raw bytes for archives with a broken name.
            let name = entry
                .name()
                .map(|name| name.into_owned())
                .unwrap_or_else(|_| String::from_utf8_lossy(entry.name_raw()).into_owned());

            let uncompressed_size = entry.size();
            if entry.is_file() && encryption != Encryption::None {
                has_encrypted_file = true;
                // A zero-length entry has CRC32 0, so a wrong ZipCrypto
                // candidate that passes the 1-byte header check would produce
                // a vacuous CRC "match". Never select an empty file when a
                // verifiable non-empty entry may exist.
                if uncompressed_size > 0 {
                    let is_smaller = match selected {
                        Some((best_size, _, _)) => uncompressed_size < best_size,
                        None => true,
                    };
                    if is_smaller {
                        selected = Some((uncompressed_size, index, encryption));
                    }
                }
            }

            entries.push(EntryInfo {
                index,
                name,
                uncompressed_size,
                compressed_size: entry.compressed_size(),
                encryption,
                crc32: entry.crc32(),
                is_dir: entry.is_dir(),
            });
        }

        let (selected, encryption) = match selected {
            Some((_, index, encryption)) => (Some(index), encryption),
            None if has_encrypted_file => {
                // There are encrypted files, but all are empty. The ZIP format
                // gives us no reliable way to distinguish the correct password
                // from a 1/256 header collision, so refuse rather than report a
                // false Hit.
                return Err(AcxError::Unsupported(
                    "encrypted archive has only zero-length file entries; cannot verify candidates"
                        .to_string(),
                ));
            }
            None => (None, Encryption::None),
        };

        Ok(Self {
            archive,
            info: ArchiveInfo {
                path: path.to_path_buf(),
                format: ArchiveFormat::Zip,
                encryption,
                selected,
                entries,
            },
        })
    }
}

impl ArchiveSession for ZipSession {
    fn info(&self) -> &ArchiveInfo {
        &self.info
    }

    fn test_password(&mut self, password: &[u8]) -> Result<PasswordTest> {
        let Some(index) = self.info.selected else {
            return Err(AcxError::NotEncrypted);
        };

        // The W1 engine only verifies ZipCrypto. AES would need the crate's
        // `aes-crypto` feature and PBKDF2/HMAC verification; report it as
        // unsupported rather than returning a misleading `Miss`.
        let selected_encryption = self.info.entries.get(index).map(|entry| entry.encryption);
        if selected_encryption != Some(Encryption::ZipCrypto) {
            return Err(AcxError::Unsupported(
                "only ZipCrypto entries are supported by this build".to_string(),
            ));
        }

        let mut entry = match self.archive.by_index_decrypt(index, password) {
            Ok(entry) => entry,
            // The 12-byte ZipCrypto check header rejected the key: a normal
            // wrong-password verdict, not an archive failure.
            Err(ZipError::InvalidPassword) => return Ok(PasswordTest::Miss),
            // Everything else (I/O, corrupt local header, missing entry,
            // unsupported encryption) says the archive cannot be probed at
            // all; swallowing it would hide real corruption from the caller.
            Err(err) => return Err(AcxError::Zip(err)),
        };

        let expected_crc = entry.crc32();
        let declared_size = entry.size();
        if declared_size > MAX_VERIFY_BYTES {
            return Err(AcxError::Unsupported(format!(
                "selected entry is {declared_size} bytes, larger than the {MAX_VERIFY_BYTES}-byte W1 verification cap"
            )));
        }

        // Read through a `take` limit as well: the declared size lives in the
        // archive and must not be trusted to bound the allocation.
        let mut bytes = Vec::new();
        if let Err(err) = (&mut entry)
            .take(MAX_VERIFY_BYTES.saturating_add(1))
            .read_to_end(&mut bytes)
        {
            // A candidate that slipped through the 1/256 ZipCrypto header
            // check decrypts to garbage: the decompressor either fails or the
            // crate's CRC reader reports a mismatch. Both surface as
            // `InvalidData`/`UnexpectedEof` and mean "this password is wrong".
            // Genuine I/O failures (disk, permissions) keep propagating so the
            // scheduler can abort instead of silently recording misses.
            if matches!(
                err.kind(),
                std::io::ErrorKind::InvalidData
                    | std::io::ErrorKind::InvalidInput
                    | std::io::ErrorKind::UnexpectedEof
            ) {
                return Ok(PasswordTest::Miss);
            }
            return Err(AcxError::Io(err));
        }

        if bytes.len() as u64 > MAX_VERIFY_BYTES {
            return Err(AcxError::Unsupported(format!(
                "selected entry decompresses past the {MAX_VERIFY_BYTES}-byte W1 verification cap"
            )));
        }

        // Defense in depth against the ZipCrypto 1/256 false header pass: only
        // a full-content CRC match counts as a hit.
        if crc32fast::hash(&bytes) == expected_crc {
            Ok(PasswordTest::Hit)
        } else {
            Ok(PasswordTest::Miss)
        }
    }
}

/// Opens a fresh [`ZipSession`] per scheduler worker.
pub struct ZipFactory {
    pub path: PathBuf,
}

impl ArchiveSessionFactory for ZipFactory {
    fn open(&self) -> Result<Box<dyn ArchiveSession>> {
        Ok(Box::new(ZipSession::open(&self.path)?))
    }
}

/// Scan a ZIP extra-field blob for the WinZip AES header id.
///
/// [`zip::read::ZipFile::extra_data`] serializes each field as
/// `[header id: u16 LE][payload length: u16 LE][payload]`, so a linear walk is
/// enough. Malformed trailing bytes end the scan instead of panicking; the
/// field is only used as a hint to label the encryption scheme.
fn has_aes_extra_field(extra: Option<&[u8]>) -> bool {
    let Some(mut blob) = extra else {
        return false;
    };
    while blob.len() >= 4 {
        let header_id = u16::from_le_bytes([blob[0], blob[1]]);
        let payload_len = usize::from(u16::from_le_bytes([blob[2], blob[3]]));
        if header_id == AES_EXTRA_FIELD_ID {
            return true;
        }
        let Some(field_len) = payload_len.checked_add(4) else {
            return false;
        };
        if field_len > blob.len() {
            return false;
        }
        blob = &blob[field_len..];
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};
    use std::sync::OnceLock;
    use zip::unstable::write::FileOptionsExt;
    use zip::write::SimpleFileOptions;
    use zip::{CompressionMethod, ZipWriter};

    const PASSWORD: &[u8] = b"P@ssw0rd123";
    const HELLO: &[u8] = b"ArchCracker W1 fixture";
    const PADDING: [u8; 64] = [b'x'; 64];

    /// Directory for fixture archives, preferring the OS temp directory.
    ///
    /// Confined CI/sandbox setups sometimes hand the test process a `TMP` it
    /// may not write to (even when the launching shell can). In that case fall
    /// back to a scratch directory beside the test binary inside the build's
    /// `target/` tree, which is writable and never committed.
    fn scratch_dir() -> &'static Path {
        static SCRATCH: OnceLock<PathBuf> = OnceLock::new();
        SCRATCH.get_or_init(|| {
            let preferred = std::env::temp_dir();
            let probe = preferred.join(format!("acx-w1-probe-{}.tmp", std::process::id()));
            let writable = std::fs::write(&probe, b"probe").is_ok();
            let _ = std::fs::remove_file(&probe);
            if writable {
                return preferred;
            }

            let mut fallback = std::env::current_exe().unwrap_or_default();
            if fallback.pop() {
                fallback.pop();
            }
            fallback.push("acx-test-tmp");
            let _ = std::fs::create_dir_all(&fallback);
            fallback
        })
    }

    /// Temporary archive path that removes the file when the test ends.
    struct TempArchive {
        path: PathBuf,
    }

    impl TempArchive {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos())
                .unwrap_or(0);
            let name = format!("acx-w1-zip-{tag}-{}-{nanos}.zip", std::process::id());
            Self {
                path: scratch_dir().join(name),
            }
        }

        fn write(&self, bytes: &[u8]) {
            std::fs::write(&self.path, bytes).expect("write temporary zip");
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempArchive {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    /// Build a ZipCrypto ZIP holding `hello.txt` plus a larger encrypted entry
    /// so the "smallest encrypted file" selection is observable.
    fn zipcrypto_zip() -> Vec<u8> {
        encrypted_zip(
            &[("hello.txt", HELLO), ("padding.txt", &PADDING)],
            CompressionMethod::Stored,
        )
    }

    /// Build a ZipCrypto ZIP from `(name, plaintext)` entries.
    fn encrypted_zip(entries: &[(&str, &[u8])], compression: CompressionMethod) -> Vec<u8> {
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        for (name, contents) in entries {
            let options = SimpleFileOptions::default()
                .compression_method(compression)
                .with_deprecated_encryption(PASSWORD)
                .expect("ZipCrypto file options");
            writer.start_file(*name, options).expect("start entry");
            writer.write_all(contents).expect("write entry");
        }
        writer.finish().expect("finish zip").into_inner()
    }

    /// Build an unencrypted, stored ZIP with a single `hello.txt` entry.
    fn plain_zip() -> Vec<u8> {
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
        writer
            .start_file("hello.txt", options)
            .expect("start hello.txt");
        writer.write_all(HELLO).expect("write hello.txt");
        writer.finish().expect("finish zip").into_inner()
    }

    fn open_session(bytes: &[u8], tag: &str) -> (TempArchive, ZipSession) {
        let temp = TempArchive::new(tag);
        temp.write(bytes);
        let session = ZipSession::open(temp.path()).expect("open temporary zip");
        (temp, session)
    }

    #[test]
    fn preflight_selects_smallest_encrypted_entry() {
        let (_temp, session) = open_session(&zipcrypto_zip(), "encrypted");
        let info = session.info();

        assert_eq!(info.format, ArchiveFormat::Zip);
        assert_eq!(info.encryption, Encryption::ZipCrypto);
        assert_eq!(info.entries.len(), 2);

        let selected = info.selected.expect("encrypted entry must be selected");
        assert_eq!(selected, info.entries[selected].index);
        assert_eq!(info.entries[selected].name, "hello.txt");
        assert_eq!(info.entries[selected].encryption, Encryption::ZipCrypto);
        assert_eq!(info.entries[selected].uncompressed_size, HELLO.len() as u64);
        assert_eq!(info.entries[selected].crc32, crc32fast::hash(HELLO));
        assert_eq!(
            info.entries
                .iter()
                .filter(|entry| entry.encryption == Encryption::ZipCrypto)
                .count(),
            2
        );
    }

    #[test]
    fn correct_password_is_hit() {
        let (_temp, mut session) = open_session(&zipcrypto_zip(), "correct");
        assert_eq!(
            session.test_password(PASSWORD).expect("test password"),
            PasswordTest::Hit
        );
    }

    #[test]
    fn wrong_password_is_miss() {
        let (_temp, mut session) = open_session(&zipcrypto_zip(), "wrong");
        assert_eq!(
            session
                .test_password(b"definitely-not-the-password")
                .expect("test password"),
            PasswordTest::Miss
        );
    }

    #[test]
    fn empty_password_is_miss() {
        let (_temp, mut session) = open_session(&zipcrypto_zip(), "empty");
        assert_eq!(
            session.test_password(b"").expect("test password"),
            PasswordTest::Miss
        );
    }

    #[test]
    fn unencrypted_zip_has_no_selection() {
        let (_temp, mut session) = open_session(&plain_zip(), "plain");
        let info = session.info();

        assert_eq!(info.encryption, Encryption::None);
        assert_eq!(info.selected, None);
        assert!(info
            .entries
            .iter()
            .all(|entry| entry.encryption == Encryption::None));
        assert!(matches!(
            session.test_password(PASSWORD),
            Err(AcxError::NotEncrypted)
        ));
    }

    #[test]
    fn empty_archive_is_rejected() {
        let writer = ZipWriter::new(Cursor::new(Vec::new()));
        let bytes = writer.finish().expect("finish empty zip").into_inner();
        let temp = TempArchive::new("empty");
        temp.write(&bytes);

        assert!(matches!(
            ZipSession::open(temp.path()),
            Err(AcxError::EmptyArchive)
        ));
    }

    #[test]
    fn deflated_wrong_candidates_are_misses_not_errors() {
        // A 1/256 ZipCrypto header collision on a deflated entry must not
        // abort the whole attack with a corrupt-deflate I/O error.
        let bytes = encrypted_zip(&[("hello.txt", HELLO)], CompressionMethod::Deflated);
        let (_temp, mut session) = open_session(&bytes, "deflate");

        for index in 0..5_000 {
            let candidate = format!("wrong-{index}");
            let outcome = session
                .test_password(candidate.as_bytes())
                .unwrap_or_else(|error| panic!("candidate {index} returned error: {error}"));
            assert_eq!(outcome, PasswordTest::Miss, "candidate {index} falsely hit");
        }
    }

    #[test]
    fn zero_length_encrypted_entry_is_refused() {
        // CRC32 of an empty plaintext is 0, so the CRC gate cannot distinguish
        // a correct password from a header collision. Refuse instead of
        // reporting a false Hit.
        let bytes = encrypted_zip(&[("empty.txt", &[])], CompressionMethod::Stored);
        let temp = TempArchive::new("zero-length");
        temp.write(&bytes);

        assert!(matches!(
            ZipSession::open(temp.path()),
            Err(AcxError::Unsupported(_))
        ));
    }

    #[test]
    fn selects_non_empty_entry_over_zero_length_entry() {
        let bytes = encrypted_zip(
            &[("empty.txt", &[]), ("hello.txt", HELLO)],
            CompressionMethod::Stored,
        );
        let (_temp, session) = open_session(&bytes, "mixed-empty");

        let selected = session
            .info()
            .selected_entry()
            .expect("non-empty encrypted entry must be selected");
        assert_eq!(selected.name, "hello.txt");
        assert_eq!(selected.uncompressed_size, HELLO.len() as u64);
    }

    #[test]
    fn aes_extra_field_is_detected_by_extra_data_scan() {
        // The crate cannot write AES without its `aes-crypto` feature, so the
        // scanner is exercised on serialized extra-field blobs instead.
        // `hello` is a ZipCrypto-encrypted entry: no 0x9901 field.
        let zipcrypto_extra = [0x55, 0x54, 0x05, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
        assert!(!has_aes_extra_field(Some(&zipcrypto_extra)));
        assert!(!has_aes_extra_field(None));

        // WinZip AES field: header id 0x9901, length 7, "AE" + vendor + strength + method.
        let aes_extra = [
            0x01, 0x99, 0x07, 0x00, 0x02, 0x00, b'A', b'E', 0x03, 0x00, 0x00,
        ];
        assert!(has_aes_extra_field(Some(&aes_extra)));

        // A preceding zip64 field must not stop the scan.
        let mut mixed = vec![0x01, 0x00, 0x00, 0x00];
        mixed.extend_from_slice(&aes_extra);
        assert!(has_aes_extra_field(Some(&mixed)));

        // Truncated or trailing garbage must be ignored, not panic. A bare
        // 0x9901 id is still enough to label the entry as AES.
        assert!(has_aes_extra_field(Some(&[0x01, 0x99, 0xff, 0x00])));
        assert!(!has_aes_extra_field(Some(&[0x55, 0x54, 0x05, 0x00, 0x01])));
        assert!(!has_aes_extra_field(Some(&[0x01, 0x99])));
    }

    #[test]
    fn factory_opens_independent_sessions() {
        let temp = TempArchive::new("factory");
        temp.write(&zipcrypto_zip());

        let factory = ZipFactory {
            path: temp.path().to_path_buf(),
        };
        let mut first = factory.open().expect("first session");
        let mut second = factory.open().expect("second session");

        assert_eq!(
            first.test_password(PASSWORD).expect("first password"),
            PasswordTest::Hit
        );
        assert_eq!(
            second.test_password(PASSWORD).expect("second password"),
            PasswordTest::Hit
        );
    }
}
