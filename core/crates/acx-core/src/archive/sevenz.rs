// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

//! 7z engine: AES-256 content/header decryption and first-block probing.
//!
//! `sevenz-rust2` exposes the parsed archive (`Archive`) separately from the
//! source reader (`BlockDecoder`). We keep that split: metadata is parsed once
//! per worker and reused for every candidate, while a candidate only pays for
//! the AES key derivation and the first block.
//!
//! Candidate handling has two tiers:
//!
//! 1. **Probe** the first file of the selected encrypted block and stop after a
//!    small prefix. A wrong password almost always makes the outer LZMA/LZMA2
//!    decoder fail immediately (7z AES encrypts the compressed stream).
//! 2. **Verify** the complete selected entry with its CRC32. Only this tier may
//!    return [`PasswordTest::Hit`]. Stored (`COPY`) entries cannot be rejected
//!    by a structural probe, so the full CRC check is what distinguishes them.
//!
//! Header encryption (`-mhe=on`) is different: the archive metadata itself is
//! AES-encrypted, so the header CRC is checked during `Archive::read` before any
//! entry is known. A successful parse is still followed by the full entry CRC
//! check before returning a hit.

use super::info::{ArchiveFormat, ArchiveInfo, Encryption, EntryInfo, PasswordTest};
use super::{ArchiveSession, ArchiveSessionFactory};
use crate::error::{AcxError, Result};
use sevenz_rust2::{Archive, BlockDecoder, EncoderMethod, Error as SevenZError, Password};
use std::fs::File;
use std::path::{Path, PathBuf};

/// Hard cap for one full verification pass. W1 targets the smallest entry; a
/// larger entry is refused rather than turning a candidate test into a
/// multi-gigabyte decompression.
const MAX_VERIFY_BYTES: u64 = 64 * 1024 * 1024;

/// How much plaintext the first-block probe reads before declaring the
/// candidate structurally plausible.
const PROBE_BYTES: u64 = 64 * 1024;

/// One open 7z archive, owned by a scheduler worker.
pub struct SevenZSession {
    path: PathBuf,
    info: ArchiveInfo,
    /// Parsed metadata for archives whose headers are not encrypted. Header
    /// encrypted archives cannot be parsed until a candidate is supplied, so
    /// this is `None` and each test re-reads the header with that candidate.
    archive: Option<Archive>,
}

impl SevenZSession {
    /// Open `path`, parse the metadata, and pick a verification target.
    ///
    /// An empty password is sufficient to parse an unencrypted header. A 7z
    /// header-encrypted archive returns `PasswordRequired`, which is recorded
    /// as `header_encrypted` rather than treated as an error.
    pub fn open(path: &Path) -> Result<Self> {
        let (archive, header_encrypted) = read_metadata(path)?;
        if header_encrypted {
            return Ok(Self {
                path: path.to_path_buf(),
                info: ArchiveInfo {
                    path: path.to_path_buf(),
                    format: ArchiveFormat::SevenZ,
                    encryption: Encryption::Aes,
                    selected: None,
                    whole_archive: false,
                    header_encrypted: true,
                    entries: Vec::new(),
                },
                archive: None,
            });
        }

        let archive = archive.ok_or_else(|| {
            AcxError::Internal("7z metadata parser returned no archive".to_string())
        })?;
        if archive.files.is_empty() {
            return Err(AcxError::EmptyArchive);
        }

        let encrypted = archive_uses_aes(&archive);
        let selected = if encrypted {
            Some(select_target(&archive).ok_or_else(|| {
                AcxError::Unsupported(
                    "7z archive has no non-empty encrypted entry with a CRC to verify".to_string(),
                )
            })?)
        } else {
            None
        };

        let info = ArchiveInfo {
            path: path.to_path_buf(),
            format: ArchiveFormat::SevenZ,
            encryption: if encrypted {
                Encryption::Aes
            } else {
                Encryption::None
            },
            selected,
            whole_archive: false,
            header_encrypted: false,
            entries: describe_entries(&archive),
        };
        Ok(Self {
            path: path.to_path_buf(),
            info,
            archive: Some(archive),
        })
    }

    /// Metadata parsed by this session (used by [`SevenZFactory`]).
    pub fn info(&self) -> &ArchiveInfo {
        &self.info
    }

    fn test_file_encrypted(&mut self, password: &[u8]) -> Result<PasswordTest> {
        let Some(target) = self.info.selected else {
            return Err(AcxError::NotEncrypted);
        };
        let archive = self
            .archive
            .as_ref()
            .ok_or_else(|| AcxError::Internal("7z session has no parsed archive".to_string()))?;
        if archive.files[target].size > MAX_VERIFY_BYTES {
            return Err(AcxError::Unsupported(format!(
                "selected 7z entry is {} bytes, larger than the {MAX_VERIFY_BYTES}-byte W1 verification cap",
                archive.files[target].size
            )));
        }

        let Some(password) = encode_password(password) else {
            // A dictionary entry that is not valid UTF-8 cannot be represented
            // as a 7z UTF-16 password; it is a miss, not an archive error.
            return Ok(PasswordTest::Miss);
        };
        let block = archive.stream_map.file_block_index[target]
            .ok_or_else(|| AcxError::Internal(format!("7z entry {target} has no block")))?;

        // Tier 1: decrypt/decompress only a prefix of the first file in the
        // block. A wrong key normally fails here, before the full entry is read.
        //
        // A COPY-only block has no compression structure for the probe to
        // reject, so skipping it avoids a second AES KDF; the full CRC check
        // below is the only meaningful test for stored entries.
        if !block_is_stored(archive, block) {
            let mut probe_file = File::open(&self.path)?;
            match probe_first_file(&mut probe_file, archive, block, &password) {
                Ok(()) => {}
                Err(error) if is_candidate_rejection(&error) => return Ok(PasswordTest::Miss),
                Err(error) => return Err(AcxError::SevenZ(error)),
            }
        }

        // Tier 2: consume the selected entry to EOF so the crate verifies its
        // CRC32 (and, for the last entry of a block, the block CRC).
        let mut verify_file = File::open(&self.path)?;
        match verify_target(&mut verify_file, archive, target, &password) {
            Ok(()) => Ok(PasswordTest::Hit),
            Err(error) if is_candidate_rejection(&error) => Ok(PasswordTest::Miss),
            Err(error) => Err(AcxError::SevenZ(error)),
        }
    }

    fn test_header_encrypted(&self, password: &[u8]) -> Result<PasswordTest> {
        let Some(password) = encode_password(password) else {
            return Ok(PasswordTest::Miss);
        };
        let mut file = File::open(&self.path)?;
        let archive = match Archive::read(&mut file, &password) {
            Ok(archive) => archive,
            Err(error) if is_candidate_rejection(&error) => return Ok(PasswordTest::Miss),
            Err(error) => return Err(AcxError::SevenZ(error)),
        };
        if archive.files.is_empty() {
            return Err(AcxError::EmptyArchive);
        }
        let target = select_target(&archive).ok_or_else(|| {
            AcxError::Unsupported(
                "7z archive has no non-empty encrypted entry with a CRC to verify".to_string(),
            )
        })?;
        if archive.files[target].size > MAX_VERIFY_BYTES {
            return Err(AcxError::Unsupported(format!(
                "selected 7z entry is {} bytes, larger than the {MAX_VERIFY_BYTES}-byte W1 verification cap",
                archive.files[target].size
            )));
        }

        match verify_target(&mut file, &archive, target, &password) {
            Ok(()) => Ok(PasswordTest::Hit),
            Err(error) if is_candidate_rejection(&error) => Ok(PasswordTest::Miss),
            Err(error) => Err(AcxError::SevenZ(error)),
        }
    }
}

impl ArchiveSession for SevenZSession {
    fn info(&self) -> &ArchiveInfo {
        &self.info
    }

    fn test_password(&mut self, password: &[u8]) -> Result<PasswordTest> {
        if self.info.header_encrypted {
            self.test_header_encrypted(password)
        } else if self.info.encryption == Encryption::Aes {
            self.test_file_encrypted(password)
        } else {
            Err(AcxError::NotEncrypted)
        }
    }
}

/// Opens a fresh [`SevenZSession`] per scheduler worker.
///
/// The metadata is parsed once when the factory is created; workers clone the
/// cached [`Archive`] instead of re-reading the header. Header-encrypted
/// archives are the exception: their metadata cannot be parsed without a
/// password, so each worker tests candidates directly.
#[derive(Debug)]
pub struct SevenZFactory {
    pub path: PathBuf,
    info: ArchiveInfo,
    archive: Option<Archive>,
}

impl SevenZFactory {
    /// Parse `path` once and build a factory around the result.
    pub fn new(path: PathBuf) -> Result<Self> {
        let session = SevenZSession::open(&path)?;
        Ok(Self {
            path,
            info: session.info,
            archive: session.archive,
        })
    }

    /// Reuse metadata produced by [`super::preflight`] without probing again.
    ///
    /// The header is parsed a second time to obtain the [`Archive`] value that
    /// `ArchiveInfo` intentionally does not carry. This is still two parses per
    /// attack (preflight + this call), not one per worker.
    pub fn from_info(path: PathBuf, info: ArchiveInfo) -> Result<Self> {
        if info.format != ArchiveFormat::SevenZ {
            return Err(AcxError::Unsupported(format!(
                "not a 7z archive (format {})",
                info.format.as_str()
            )));
        }
        if !same_archive(&path, &info.path) {
            return Err(AcxError::Unsupported(
                "cached 7z metadata belongs to a different archive".to_string(),
            ));
        }
        let archive = if info.header_encrypted {
            None
        } else {
            let (archive, header_encrypted) = read_metadata(&path)?;
            if header_encrypted {
                return Err(AcxError::Unsupported(
                    "archive header is encrypted but cached metadata says it is not".to_string(),
                ));
            }
            Some(archive.ok_or_else(|| {
                AcxError::Internal("7z metadata parser returned no archive".to_string())
            })?)
        };
        Ok(Self {
            path,
            info,
            archive,
        })
    }

    /// Metadata probed when this factory was created.
    pub fn info(&self) -> &ArchiveInfo {
        &self.info
    }
}

impl ArchiveSessionFactory for SevenZFactory {
    fn open(&self) -> Result<Box<dyn ArchiveSession>> {
        Ok(Box::new(SevenZSession {
            path: self.path.clone(),
            info: self.info.clone(),
            archive: self.archive.clone(),
        }))
    }
}

/// Parse the unencrypted part of the 7z header.
///
/// Returns `(metadata, header_encrypted)`. A `PasswordRequired` from an empty
/// password is the crate's signal that the encoded header uses AES; every other
/// error is a malformed or unsupported archive.
fn read_metadata(path: &Path) -> Result<(Option<Archive>, bool)> {
    let mut file = File::open(path)?;
    match Archive::read(&mut file, &Password::empty()) {
        Ok(archive) => Ok((Some(archive), false)),
        Err(SevenZError::PasswordRequired) => Ok((None, true)),
        Err(error) => Err(AcxError::SevenZ(error)),
    }
}

/// Convert the scheduler's UTF-8 candidate bytes to 7z's UTF-16LE password.
fn encode_password(password: &[u8]) -> Option<Password> {
    std::str::from_utf8(password).ok().map(Password::from)
}

fn archive_uses_aes(archive: &Archive) -> bool {
    (0..archive.blocks.len()).any(|block| block_uses_aes(archive, block))
}

fn block_uses_aes(archive: &Archive, block_index: usize) -> bool {
    archive.blocks.get(block_index).is_some_and(|block| {
        block
            .coders
            .iter()
            .any(|coder| coder.encoder_method_id() == EncoderMethod::ID_AES256_SHA256)
    })
}

/// Whether the block contains a COPY coder. Such a block has no compressed
/// structure for the first-block probe to reject, so the full CRC is the only
/// meaningful candidate check.
fn block_is_stored(archive: &Archive, block_index: usize) -> bool {
    archive.blocks.get(block_index).is_some_and(|block| {
        block
            .coders
            .iter()
            .any(|coder| coder.encoder_method_id() == EncoderMethod::ID_COPY)
    })
}

/// Select the first CRC-protected, non-empty file of an encrypted block.
///
/// Choosing the first file of a block means a solid block does not have to
/// decompress bytes that precede the target. The smallest such candidate
/// across blocks wins, matching the ZIP engine's "smallest verifiable entry"
/// policy.
fn select_target(archive: &Archive) -> Option<usize> {
    let mut best: Option<(u64, usize)> = None;
    for block_index in 0..archive.blocks.len() {
        if !block_uses_aes(archive, block_index) {
            continue;
        }
        let Some(&start) = archive.stream_map.block_first_file_index.get(block_index) else {
            continue;
        };
        let Some(file) = archive.files.get(start) else {
            continue;
        };
        if !file.has_stream
            || file.is_directory
            || file.is_anti_item
            || file.size == 0
            || !file.has_crc
        {
            continue;
        }
        if archive
            .stream_map
            .file_block_index
            .get(start)
            .copied()
            .flatten()
            != Some(block_index)
        {
            continue;
        }
        if best.is_none_or(|(size, _)| file.size < size) {
            best = Some((file.size, start));
        }
    }
    best.map(|(_, index)| index)
}

fn describe_entries(archive: &Archive) -> Vec<EntryInfo> {
    archive
        .files
        .iter()
        .enumerate()
        .map(|(index, file)| EntryInfo {
            index,
            name: file.name.clone(),
            uncompressed_size: file.size,
            compressed_size: file.compressed_size,
            encryption: match archive
                .stream_map
                .file_block_index
                .get(index)
                .copied()
                .flatten()
            {
                Some(block) if block_uses_aes(archive, block) => Encryption::Aes,
                _ => Encryption::None,
            },
            crc32: file.crc as u32,
            is_dir: file.is_directory,
        })
        .collect()
}

/// Read a prefix of the first file in `block` to reject an obviously wrong key.
fn probe_first_file(
    file: &mut File,
    archive: &Archive,
    block: usize,
    password: &Password,
) -> std::result::Result<(), SevenZError> {
    let decoder = BlockDecoder::new(1, block, archive, password, file);
    let mut buf = [0u8; 4096];
    decoder.for_each_entries(&mut |_entry, reader| {
        let mut total = 0u64;
        while total < PROBE_BYTES {
            let want = (PROBE_BYTES - total).min(buf.len() as u64) as usize;
            let read = reader.read(&mut buf[..want])?;
            if read == 0 {
                break;
            }
            total += read as u64;
        }
        Ok(false)
    })?;
    Ok(())
}

/// Read the complete target entry and let the crate verify its CRC.
fn verify_target(
    file: &mut File,
    archive: &Archive,
    target: usize,
    password: &Password,
) -> std::result::Result<(), SevenZError> {
    let block = archive.stream_map.file_block_index[target]
        .ok_or_else(|| SevenZError::Other("7z target entry has no block".into()))?;
    let start = archive
        .stream_map
        .block_first_file_index
        .get(block)
        .copied()
        .ok_or_else(|| SevenZError::Other("7z block has no first file".into()))?;
    let decoder = BlockDecoder::new(1, block, archive, password, file);
    let mut hit = false;
    let mut offset = 0usize;
    let mut buf = [0u8; 8192];
    decoder.for_each_entries(&mut |_entry, reader| {
        let current = start + offset;
        offset += 1;
        if current == target {
            let expected = archive.files[target].size;
            let mut total = 0u64;
            loop {
                let read = reader.read(&mut buf)?;
                if read == 0 {
                    break;
                }
                total += read as u64;
                if total > MAX_VERIFY_BYTES {
                    return Err(SevenZError::Other(
                        "7z entry exceeded the W1 verification cap".into(),
                    ));
                }
            }
            if total != expected {
                return Err(SevenZError::Io(
                    std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "7z entry ended before its declared size",
                    ),
                    "".into(),
                ));
            }
            hit = true;
            Ok(false)
        } else {
            // In a solid block, the target can only be reached by consuming the
            // entries in front of it. They are discarded without buffering.
            std::io::copy(reader, &mut std::io::sink())?;
            Ok(true)
        }
    })?;
    if hit {
        Ok(())
    } else {
        Err(SevenZError::Other(
            "7z target entry was not found in its block".into(),
        ))
    }
}

/// Errors that mean "this candidate is wrong" instead of "the archive or disk
/// is broken". 7z AES has no authenticator; a wrong key surfaces as a failed
/// header CRC, a failed entry CRC, or a malformed LZMA/LZMA2 stream.
fn is_candidate_rejection(error: &SevenZError) -> bool {
    match error {
        SevenZError::PasswordRequired
        | SevenZError::MaybeBadPassword(_)
        | SevenZError::ChecksumVerificationFailed
        | SevenZError::NextHeaderCrcMismatch => true,
        SevenZError::Io(error, _) => matches!(
            error.kind(),
            std::io::ErrorKind::InvalidData
                | std::io::ErrorKind::InvalidInput
                | std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::Other
        ),
        _ => false,
    }
}

/// Compare two paths, resolving them when possible so `.\a.7z` and `a.7z` are
/// recognized as the same archive on Windows.
fn same_archive(left: &Path, right: &Path) -> bool {
    if left == right {
        return true;
    }
    match (std::fs::canonicalize(left), std::fs::canonicalize(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sevenz_rust2::encoder_options::AesEncoderOptions;
    use sevenz_rust2::{
        ArchiveEntry, ArchiveWriter, EncoderConfiguration, EncoderMethod, SourceReader,
    };
    use std::io::Cursor;
    use std::sync::OnceLock;

    const PASSWORD: &str = "P@ssw0rd123";
    const HELLO: &[u8] = b"ArchCracker W1 7z unit fixture";
    const PADDING: [u8; 4096] = [b'x'; 4096];

    fn scratch_dir() -> &'static Path {
        static SCRATCH: OnceLock<PathBuf> = OnceLock::new();
        SCRATCH.get_or_init(|| {
            let preferred = std::env::temp_dir();
            let probe = preferred.join(format!("acx-w1-7z-probe-{}.tmp", std::process::id()));
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

    struct TempArchive {
        path: PathBuf,
    }

    impl TempArchive {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos())
                .unwrap_or(0);
            let name = format!("acx-w1-7z-{tag}-{}-{nanos}.7z", std::process::id());
            Self {
                path: scratch_dir().join(name),
            }
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

    /// Build a 7z archive. `methods` is the encode order (compression first,
    /// AES second). The header is encrypted only when requested.
    fn write_7z(
        path: &Path,
        entries: &[(&str, &[u8])],
        encrypted: bool,
        header_encrypted: bool,
        stored: bool,
        solid: bool,
    ) {
        write_7z_with_method(
            path,
            entries,
            if stored {
                EncoderMethod::COPY
            } else {
                EncoderMethod::LZMA2
            },
            encrypted,
            header_encrypted,
            solid,
        );
    }

    fn write_7z_with_method(
        path: &Path,
        entries: &[(&str, &[u8])],
        method: EncoderMethod,
        encrypted: bool,
        header_encrypted: bool,
        solid: bool,
    ) {
        let mut writer = ArchiveWriter::create(path).expect("create 7z");
        writer.set_encrypt_header(header_encrypted);
        let mut methods = vec![EncoderConfiguration::new(method)];
        if encrypted {
            methods.push(AesEncoderOptions::new(Password::from(PASSWORD)).into());
        }
        writer.set_content_methods(methods);

        if solid {
            let archive_entries = entries
                .iter()
                .map(|(name, _)| ArchiveEntry::new_file(name))
                .collect();
            let readers = entries
                .iter()
                .map(|(_, contents)| SourceReader::new(Cursor::new(contents.to_vec())))
                .collect();
            writer
                .push_archive_entries(archive_entries, readers)
                .expect("push solid entries");
        } else {
            for (name, contents) in entries {
                writer
                    .push_archive_entry(
                        ArchiveEntry::new_file(name),
                        Some(Cursor::new(contents.to_vec())),
                    )
                    .expect("push entry");
            }
        }
        writer.finish().expect("finish 7z");
    }

    fn open_session(path: &Path) -> SevenZSession {
        SevenZSession::open(path).expect("open 7z session")
    }

    #[test]
    fn unencrypted_archive_is_not_a_target() {
        let temp = TempArchive::new("plain");
        write_7z(
            temp.path(),
            &[("hello.txt", HELLO)],
            false,
            false,
            false,
            false,
        );
        let mut session = open_session(temp.path());

        assert_eq!(session.info().format, ArchiveFormat::SevenZ);
        assert_eq!(session.info().encryption, Encryption::None);
        assert_eq!(session.info().selected, None);
        assert!(!session.info().header_encrypted);
        assert!(matches!(
            session.test_password(PASSWORD.as_bytes()),
            Err(AcxError::NotEncrypted)
        ));
    }

    #[test]
    fn aes_file_encryption_verifies_correct_and_rejects_wrong() {
        let temp = TempArchive::new("file-aes");
        write_7z(
            temp.path(),
            &[("hello.txt", HELLO), ("padding.txt", &PADDING)],
            true,
            false,
            false,
            false,
        );
        let mut session = open_session(temp.path());
        let info = session.info();

        assert_eq!(info.encryption, Encryption::Aes);
        assert!(!info.header_encrypted);
        let selected = info.selected_entry().expect("selected entry");
        assert_eq!(selected.name, "hello.txt");
        assert_eq!(selected.uncompressed_size, HELLO.len() as u64);
        assert_eq!(selected.encryption, Encryption::Aes);

        assert_eq!(
            session.test_password(PASSWORD.as_bytes()).expect("correct"),
            PasswordTest::Hit
        );
        assert_eq!(
            session.test_password(b"definitely-wrong").expect("wrong"),
            PasswordTest::Miss
        );
        assert_eq!(
            session.test_password(b"").expect("empty"),
            PasswordTest::Miss
        );
    }

    #[test]
    fn aes_header_encryption_verifies_correct_and_rejects_wrong() {
        let temp = TempArchive::new("header-aes");
        write_7z(
            temp.path(),
            &[("hello.txt", HELLO)],
            true,
            true,
            false,
            false,
        );
        let mut session = open_session(temp.path());

        assert_eq!(session.info().encryption, Encryption::Aes);
        assert!(session.info().header_encrypted);
        assert!(session.info().has_verification_target());
        assert_eq!(session.info().selected, None);
        assert!(session.info().entries.is_empty());

        assert_eq!(
            session.test_password(PASSWORD.as_bytes()).expect("correct"),
            PasswordTest::Hit
        );
        assert_eq!(
            session.test_password(b"definitely-wrong").expect("wrong"),
            PasswordTest::Miss
        );
        assert_eq!(
            session.test_password(b"").expect("empty"),
            PasswordTest::Miss
        );
    }

    #[test]
    fn stored_aes_entries_need_the_full_crc_check() {
        // COPY gives the first-block probe no structure to reject. The full
        // entry read + CRC must still return Miss for a wrong candidate.
        let temp = TempArchive::new("stored-aes");
        write_7z(
            temp.path(),
            &[("hello.txt", HELLO)],
            true,
            false,
            true,
            false,
        );
        let mut session = open_session(temp.path());

        assert_eq!(
            session.test_password(PASSWORD.as_bytes()).expect("correct"),
            PasswordTest::Hit
        );
        assert_eq!(
            session.test_password(b"wrong").expect("wrong"),
            PasswordTest::Miss
        );
    }

    #[test]
    fn aes_supported_compression_methods_verify() {
        for (index, method) in [
            EncoderMethod::COPY,
            EncoderMethod::LZMA,
            EncoderMethod::LZMA2,
            EncoderMethod::BZIP2,
            EncoderMethod::PPMD,
        ]
        .into_iter()
        .enumerate()
        {
            let tag = format!("method-{index}");
            let temp = TempArchive::new(&tag);
            write_7z_with_method(
                temp.path(),
                &[("hello.txt", HELLO)],
                method,
                true,
                false,
                false,
            );
            let mut session = open_session(temp.path());
            assert_eq!(
                session.test_password(PASSWORD.as_bytes()).expect("correct"),
                PasswordTest::Hit,
                "{method:?} must accept the correct password"
            );
            assert_eq!(
                session.test_password(b"wrong").expect("wrong"),
                PasswordTest::Miss,
                "{method:?} must reject a wrong password"
            );
        }
    }

    #[test]
    fn solid_aes_archive_targets_the_first_file_of_the_block() {
        let temp = TempArchive::new("solid-aes");
        write_7z(
            temp.path(),
            &[("hello.txt", HELLO), ("padding.txt", &PADDING)],
            true,
            false,
            false,
            true,
        );
        let mut session = open_session(temp.path());

        let selected = session.info().selected_entry().expect("selected entry");
        assert_eq!(selected.name, "hello.txt");
        assert_eq!(
            session.test_password(PASSWORD.as_bytes()).expect("correct"),
            PasswordTest::Hit
        );
        assert_eq!(
            session.test_password(b"wrong").expect("wrong"),
            PasswordTest::Miss
        );
    }

    #[test]
    fn header_encrypted_solid_archive_verifies() {
        let temp = TempArchive::new("solid-header");
        write_7z(
            temp.path(),
            &[("hello.txt", HELLO), ("padding.txt", &PADDING)],
            true,
            true,
            false,
            true,
        );
        let mut session = open_session(temp.path());

        assert_eq!(
            session.test_password(PASSWORD.as_bytes()).expect("correct"),
            PasswordTest::Hit
        );
        assert_eq!(
            session.test_password(b"wrong").expect("wrong"),
            PasswordTest::Miss
        );
    }

    #[test]
    fn wrong_candidates_never_abort_a_file_encrypted_attack() {
        // 7z AES has no authenticator, so a wrong key can fail as a bad header
        // CRC, a bad entry CRC, or malformed LZMA input. Every one of those must
        // be a Miss rather than an error that stops the scheduler.
        let temp = TempArchive::new("file-wrong-loop");
        write_7z(
            temp.path(),
            &[("hello.txt", HELLO)],
            true,
            false,
            false,
            false,
        );
        let mut session = open_session(temp.path());

        for index in 0..16 {
            let candidate = format!("wrong-{index}");
            assert_eq!(
                session
                    .test_password(candidate.as_bytes())
                    .unwrap_or_else(|error| panic!("candidate {index} errored: {error}")),
                PasswordTest::Miss,
                "candidate {index} falsely hit"
            );
        }
    }

    #[test]
    fn wrong_candidates_never_abort_a_header_encrypted_attack() {
        let temp = TempArchive::new("header-wrong-loop");
        write_7z(
            temp.path(),
            &[("hello.txt", HELLO)],
            true,
            true,
            false,
            false,
        );
        let mut session = open_session(temp.path());

        // Header KDF is intentionally expensive; eight candidates are enough
        // to cover the observed error shapes without slowing the suite.
        for index in 0..8 {
            let candidate = format!("wrong-{index}");
            assert_eq!(
                session
                    .test_password(candidate.as_bytes())
                    .unwrap_or_else(|error| panic!("candidate {index} errored: {error}")),
                PasswordTest::Miss,
                "candidate {index} falsely hit"
            );
        }
    }

    #[test]
    fn empty_archive_is_rejected() {
        let temp = TempArchive::new("empty");
        write_7z(temp.path(), &[], false, false, false, false);

        assert!(matches!(
            SevenZSession::open(temp.path()),
            Err(AcxError::EmptyArchive)
        ));
    }

    #[test]
    fn corrupt_archive_is_an_error() {
        let temp = TempArchive::new("corrupt");
        write_7z(
            temp.path(),
            &[("hello.txt", HELLO)],
            false,
            false,
            false,
            false,
        );
        let mut bytes = std::fs::read(temp.path()).expect("read fixture");
        // The start-header CRC lives at offset 8; flipping it makes the archive
        // structurally invalid before any candidate is tested.
        bytes[8] ^= 0x01;
        std::fs::write(temp.path(), bytes).expect("write corrupt fixture");

        assert!(SevenZSession::open(temp.path()).is_err());
    }

    #[test]
    fn factory_opens_independent_sessions_and_reuses_metadata() {
        let temp = TempArchive::new("factory");
        write_7z(
            temp.path(),
            &[("hello.txt", HELLO)],
            true,
            false,
            false,
            false,
        );
        let factory = SevenZFactory::new(temp.path().to_path_buf()).expect("factory");
        let mut first = factory.open().expect("first session");
        let mut second = factory.open().expect("second session");

        assert_eq!(
            first.test_password(PASSWORD.as_bytes()).expect("first"),
            PasswordTest::Hit
        );
        assert_eq!(
            second.test_password(PASSWORD.as_bytes()).expect("second"),
            PasswordTest::Hit
        );
    }

    #[test]
    fn from_info_rejects_metadata_for_a_different_archive() {
        let temp = TempArchive::new("mismatch");
        write_7z(
            temp.path(),
            &[("hello.txt", HELLO)],
            true,
            false,
            false,
            false,
        );
        let info = SevenZSession::open(temp.path())
            .expect("open")
            .info()
            .clone();
        let error = SevenZFactory::from_info(PathBuf::from("other.7z"), info)
            .expect_err("metadata for another archive must be rejected");
        assert!(matches!(error, AcxError::Unsupported(_)));
    }
}
