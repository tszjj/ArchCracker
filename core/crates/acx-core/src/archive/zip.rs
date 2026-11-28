// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

//! ZIP engine: metadata preflight plus ZipCrypto and WinZip AES candidate
//! verification (W1).
//!
//! ZipCrypto uses the 12-byte check header, a full decompression, and a final
//! CRC32 comparison. WinZip AES derives keys with PBKDF2-HMAC-SHA1 and checks
//! the 2-byte verifier; a candidate that passes the verifier is only accepted
//! after the crate has read the whole entry and verified the HMAC-SHA1-80
//! authentication code. AES must not be accepted on CRC alone: AE-2 stores a
//! zero CRC and AE-1's CRC is weaker than the authentication code.

use super::info::{ArchiveFormat, ArchiveInfo, Encryption, EntryInfo, PasswordTest};
use super::source::{ArchiveSource, VolumeReader};
use super::{ArchiveSession, ArchiveSessionFactory, ArchiveStats, FilterCounts};
use crate::error::{AcxError, Result};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use zip::result::ZipError;
use zip::{HasZipMetadata, ZipArchive};

/// A fixed buffer used to stream large entries. Verification must not allocate
/// a buffer proportional to the entry size; a 1 GB archive is a W1 target.
const VERIFY_BUFFER: usize = 64 * 1024;

/// Counters shared by every `ZipSession` opened from one `ZipFactory`.
#[derive(Debug, Default)]
struct ZipCounters {
    fast_rejected: AtomicU64,
    full_attempted: AtomicU64,
}

/// One open ZIP archive, owned by a scheduler worker.
pub struct ZipSession {
    archive: ZipArchive<VolumeReader>,
    info: ArchiveInfo,
    counters: Arc<ZipCounters>,
}

impl ZipSession {
    /// Open `path` and record the metadata the scheduler needs.
    ///
    /// Entries are inspected with [`ZipArchive::by_index_raw`] so that opening
    /// an encrypted archive never requires the password. An archive without
    /// entries is rejected with [`AcxError::EmptyArchive`]; an archive without
    /// encrypted entries is *not* an error (callers decide what to do).
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_with_counters(path, Arc::new(ZipCounters::default()))
    }

    /// Open with counters supplied by a factory so all workers share them.
    fn open_with_counters(path: &Path, counters: Arc<ZipCounters>) -> Result<Self> {
        let source = ArchiveSource::resolve(path)?;
        if source.format != ArchiveFormat::Zip {
            return Err(AcxError::Unsupported(format!(
                "not a ZIP archive (detected {})",
                source.format.as_str()
            )));
        }
        let reader = source.reader()?;
        let mut archive =
            ZipArchive::new(reader).map_err(|error| classify_zip_open(&source, error))?;
        if archive.is_empty() {
            return Err(AcxError::EmptyArchive);
        }

        let mut entries = Vec::with_capacity(archive.len());
        // (uncompressed size, index, encryption) of the smallest encrypted file.
        let mut selected: Option<(u64, usize, Encryption)> = None;
        // First zero-length AES file, if any. AES authenticates even empty
        // plaintext with a 10-byte HMAC, unlike ZipCrypto, whose empty-file
        // CRC is always 0 and therefore cannot confirm a password.
        let mut empty_aes: Option<usize> = None;
        let mut has_encrypted_file = false;

        for index in 0..archive.len() {
            let entry = archive.by_index_raw(index)?;

            let encryption = if !entry.encrypted() {
                Encryption::None
            } else if entry.get_metadata().aes_settings().is_some() {
                // Use the crate's central-directory metadata, the same source
                // `by_index_decrypt` uses to select AES vs ZipCrypto. A
                // local-header-only 0x9901 field is not trusted here because
                // it could disagree with decryption.
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
                // A zero-length ZipCrypto entry has CRC32 0, so a wrong
                // candidate that passes the 1-byte header check would produce
                // a vacuous CRC "match". Never select an empty ZipCrypto entry
                // while a verifiable non-empty entry exists; empty AES entries
                // are handled separately because their HMAC still verifies.
                if uncompressed_size > 0 {
                    let is_smaller = match selected {
                        Some((best_size, _, _)) => uncompressed_size < best_size,
                        None => true,
                    };
                    if is_smaller {
                        selected = Some((uncompressed_size, index, encryption));
                    }
                } else if encryption == Encryption::Aes && empty_aes.is_none() {
                    empty_aes = Some(index);
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
            // An empty AES entry is still authenticated by its HMAC, so it is
            // a valid (if unusual) verification target.
            None if empty_aes.is_some() => (empty_aes, Encryption::Aes),
            None if has_encrypted_file => {
                // Only zero-length ZipCrypto files remain. Their CRC is 0, so
                // the format gives us no reliable way to distinguish the
                // correct password from a 1/256 header collision; refuse
                // rather than report a false Hit.
                return Err(AcxError::Unsupported(
                    "encrypted archive has only zero-length ZipCrypto entries; cannot verify candidates"
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
                whole_archive: false,
                header_encrypted: false,
                entries,
            },
            counters,
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

        let encryption = self
            .info
            .entries
            .get(index)
            .map(|entry| entry.encryption)
            .ok_or_else(|| AcxError::Internal(format!("selected entry {index} is missing")))?;

        match encryption {
            Encryption::ZipCrypto => self.test_zipcrypto(index, password),
            Encryption::Aes => self.test_aes(index, password),
            Encryption::None => Err(AcxError::NotEncrypted),
            Encryption::Rar => Err(AcxError::Unsupported(
                "RAR entries are not handled by the ZIP engine".to_string(),
            )),
        }
    }
}

impl ZipSession {
    /// Verify a legacy ZipCrypto candidate.
    fn test_zipcrypto(&mut self, index: usize, password: &[u8]) -> Result<PasswordTest> {
        let mut entry = match self.archive.by_index_decrypt(index, password) {
            Ok(entry) => {
                self.counters.full_attempted.fetch_add(1, Ordering::Relaxed);
                entry
            }
            // The 12-byte ZipCrypto check header rejected the key: a normal
            // wrong-password verdict, not an archive failure. Counted as the
            // ZIP verifier fast filter (W2-007).
            Err(ZipError::InvalidPassword) => {
                self.counters.fast_rejected.fetch_add(1, Ordering::Relaxed);
                return Ok(PasswordTest::Miss);
            }
            // Everything else (I/O, corrupt local header, missing entry,
            // unsupported encryption) says the archive cannot be probed at
            // all; swallowing it would hide real corruption from the caller.
            Err(err) => {
                self.counters.full_attempted.fetch_add(1, Ordering::Relaxed);
                return Err(AcxError::Zip(err));
            }
        };

        let expected_crc = entry.crc32();
        let declared_size = entry.size();

        // Stream the full entry with a fixed buffer; do not allocate by size.
        let mut hasher = crc32fast::Hasher::new();
        let mut total = 0u64;
        let mut buf = [0u8; VERIFY_BUFFER];
        loop {
            match entry.read(&mut buf) {
                Ok(0) => break,
                Ok(read) => {
                    hasher.update(&buf[..read]);
                    total += read as u64;
                }
                Err(err) if is_candidate_rejection(&err) => return Ok(PasswordTest::Miss),
                Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
                    return Err(AcxError::Truncated(format!(
                        "ZIP entry data ended after {total} of {declared_size} bytes"
                    )));
                }
                Err(err) => return Err(AcxError::Io(err)),
            }
        }

        if total != declared_size {
            return Err(AcxError::Truncated(format!(
                "ZIP entry data ended after {total} of {declared_size} bytes"
            )));
        }

        // Defense in depth against the ZipCrypto 1/256 false header pass: only
        // a full-content CRC match counts as a hit.
        if hasher.finalize() == expected_crc {
            Ok(PasswordTest::Hit)
        } else {
            Ok(PasswordTest::Miss)
        }
    }

    /// Verify a WinZip AES candidate (AE-1 or AE-2, AES-128/192/256).
    ///
    /// `by_index_decrypt` performs PBKDF2-HMAC-SHA1 and checks the 2-byte
    /// verifier. A verifier pass is only 1/65536 reliable, so the full entry is
    /// read to make the crate verify the HMAC-SHA1-80 authentication code. The
    /// CRC field is deliberately ignored: AE-2 stores 0 there, and the HMAC is
    /// the stronger check for both AE variants.
    fn test_aes(&mut self, index: usize, password: &[u8]) -> Result<PasswordTest> {
        let mut entry = match self.archive.by_index_decrypt(index, password) {
            Ok(entry) => {
                self.counters.full_attempted.fetch_add(1, Ordering::Relaxed);
                entry
            }
            Err(ZipError::InvalidPassword) => {
                self.counters.fast_rejected.fetch_add(1, Ordering::Relaxed);
                return Ok(PasswordTest::Miss);
            }
            Err(err) => {
                self.counters.full_attempted.fetch_add(1, Ordering::Relaxed);
                return Err(AcxError::Zip(err));
            }
        };

        let declared_size = entry.size();
        let mut total = 0u64;
        let mut buf = [0u8; VERIFY_BUFFER];
        loop {
            match entry.read(&mut buf) {
                Ok(0) => break,
                Ok(read) => total += read as u64,
                Err(err) if is_candidate_rejection(&err) => return Ok(PasswordTest::Miss),
                Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
                    return Err(AcxError::Truncated(format!(
                        "ZIP entry data ended after {total} of {declared_size} bytes"
                    )));
                }
                Err(err) => return Err(AcxError::Io(err)),
            }
        }

        if total != declared_size {
            return Err(AcxError::Truncated(format!(
                "ZIP entry data ended after {total} of {declared_size} bytes"
            )));
        }

        // Reaching EOF means the AES reader consumed the authentication code
        // and verified the HMAC. No CRC gate here (see the method docs).
        Ok(PasswordTest::Hit)
    }
}

/// Errors that mean "this candidate is wrong" rather than "the archive or disk
/// is broken". Both ZipCrypto garbage and AES authentication failures surface
/// through these kinds.
fn is_candidate_rejection(err: &std::io::Error) -> bool {
    // Wrong passwords surface as InvalidData/InvalidInput from the decrypting
    // reader. UnexpectedEof and short reads mean the archive data is truncated,
    // so they must be reported as archive errors, never as a candidate Miss.
    matches!(
        err.kind(),
        std::io::ErrorKind::InvalidData | std::io::ErrorKind::InvalidInput
    )
}

/// Turn an archive-open failure into a preflight classification instead of a
/// generic ZIP error, so the CLI can distinguish truncated from damaged.
fn classify_zip_open(source: &ArchiveSource, error: ZipError) -> AcxError {
    let classified = match error {
        ZipError::Io(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
            AcxError::Truncated("ZIP central directory is incomplete".to_string())
        }
        ZipError::Io(error) => AcxError::Io(error),
        ZipError::InvalidArchive(message)
            if message.to_ascii_lowercase().contains("central directory")
                || message.to_ascii_lowercase().contains("eocd")
                || message.to_ascii_lowercase().contains("cdfh") =>
        {
            AcxError::Truncated("ZIP central directory is missing".to_string())
        }
        ZipError::InvalidArchive(message)
            if message.to_ascii_lowercase().contains("multi-disk")
                || message.to_ascii_lowercase().contains("multi disk") =>
        {
            AcxError::Unsupported("multi-disk ZIP files are not supported".to_string())
        }
        ZipError::InvalidArchive(message) => AcxError::Corrupt(message.into_owned()),
        ZipError::UnsupportedArchive(message) => AcxError::Unsupported(message.to_string()),
        other => AcxError::Zip(other),
    };
    source.classify_incomplete(classified)
}

/// Opens a fresh [`ZipSession`] per scheduler worker and shares counters.
pub struct ZipFactory {
    pub path: PathBuf,
    counters: Arc<ZipCounters>,
}

impl ZipFactory {
    /// Create a factory with an isolated counter set.
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            counters: Arc::new(ZipCounters::default()),
        }
    }
}

impl ArchiveSessionFactory for ZipFactory {
    fn open(&self) -> Result<Box<dyn ArchiveSession>> {
        Ok(Box::new(ZipSession::open_with_counters(
            &self.path,
            Arc::clone(&self.counters),
        )?))
    }

    fn stats(&self) -> ArchiveStats {
        let fast_rejected = self.counters.fast_rejected.load(Ordering::Relaxed);
        ArchiveStats {
            fast_rejected,
            full_attempted: self.counters.full_attempted.load(Ordering::Relaxed),
            by_filter: FilterCounts {
                zip_verifier: fast_rejected,
                ..Default::default()
            },
            ..Default::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::FastFilterKind;
    use std::io::{Cursor, Write};
    use std::sync::OnceLock;
    use zip::unstable::write::FileOptionsExt;
    use zip::write::SimpleFileOptions;
    use zip::{AesMode, CompressionMethod, ZipWriter};

    const PASSWORD: &[u8] = b"P@ssw0rd123";
    const PASSWORD_STR: &str = "P@ssw0rd123";
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

    /// Build a WinZip AES ZIP from `(name, plaintext)` entries.
    fn aes_zip(
        entries: &[(&str, &[u8])],
        compression: CompressionMethod,
        mode: AesMode,
    ) -> Vec<u8> {
        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        for (name, contents) in entries {
            let options = SimpleFileOptions::default()
                .compression_method(compression)
                .with_aes_encryption(mode, PASSWORD_STR);
            writer.start_file(*name, options).expect("start AES entry");
            writer.write_all(contents).expect("write AES entry");
        }
        writer.finish().expect("finish AES zip").into_inner()
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
    fn truncated_entry_data_is_not_a_candidate_rejection() {
        use std::io::{Error, ErrorKind};

        assert!(is_candidate_rejection(&Error::new(
            ErrorKind::InvalidData,
            "wrong password"
        )));
        assert!(is_candidate_rejection(&Error::new(
            ErrorKind::InvalidInput,
            "bad verifier"
        )));
        assert!(!is_candidate_rejection(&Error::new(
            ErrorKind::UnexpectedEof,
            "truncated entry"
        )));
        assert!(!is_candidate_rejection(&Error::other("disk failure")));
    }

    fn inflate_declared_uncompressed_size(bytes: &mut [u8]) {
        // AES fixtures use a data descriptor and rely on the central directory.
        let local_size_offset = 22;
        if bytes.len() > local_size_offset + 4 {
            let local_declared = u32::from_le_bytes([
                bytes[local_size_offset],
                bytes[local_size_offset + 1],
                bytes[local_size_offset + 2],
                bytes[local_size_offset + 3],
            ]);
            if local_declared > 0 {
                bytes[local_size_offset..local_size_offset + 4]
                    .copy_from_slice(&local_declared.saturating_add(1_000).to_le_bytes());
            }
        }
        let central = bytes
            .windows(4)
            .position(|window| window == b"PK\x01\x02")
            .expect("central directory signature");
        let size_offset = central + 24; // uncompressed size in central file header
        let declared = u32::from_le_bytes([
            bytes[size_offset],
            bytes[size_offset + 1],
            bytes[size_offset + 2],
            bytes[size_offset + 3],
        ]);
        bytes[size_offset..size_offset + 4]
            .copy_from_slice(&declared.saturating_add(1_000).to_le_bytes());
    }

    #[test]
    fn truncated_aes_entry_is_not_a_miss() {
        let mut bytes = aes_zip(
            &[("hello.txt", HELLO)],
            CompressionMethod::Stored,
            AesMode::Aes256,
        );
        inflate_declared_uncompressed_size(&mut bytes);
        let temp = TempArchive::new("truncated-aes-entry");
        temp.write(&bytes);
        let mut session =
            ZipSession::open(temp.path()).expect("preflight must still open the archive");
        let error = session
            .test_password(PASSWORD)
            .expect_err("truncated entry must not be a Miss");
        assert!(
            matches!(error, AcxError::Truncated(_) | AcxError::Io(_)),
            "unexpected error: {error:?}"
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
    fn preflight_detects_aes_and_selects_smallest_entry() {
        let bytes = aes_zip(
            &[("hello.txt", HELLO), ("padding.txt", &PADDING)],
            CompressionMethod::Stored,
            AesMode::Aes256,
        );
        let (_temp, session) = open_session(&bytes, "aes-preflight");
        let info = session.info();

        assert_eq!(info.encryption, Encryption::Aes);
        assert_eq!(info.entries.len(), 2);
        assert!(info
            .entries
            .iter()
            .all(|entry| entry.encryption == Encryption::Aes));

        let selected = info.selected_entry().expect("AES entry must be selected");
        assert_eq!(selected.name, "hello.txt");
        assert_eq!(selected.uncompressed_size, HELLO.len() as u64);
    }

    #[test]
    fn aes_modes_and_compression_methods_verify() {
        for mode in [AesMode::Aes128, AesMode::Aes192, AesMode::Aes256] {
            for compression in [CompressionMethod::Stored, CompressionMethod::Deflated] {
                let bytes = aes_zip(&[("hello.txt", HELLO)], compression, mode);
                let tag = format!("aes-{mode:?}-{compression:?}");
                let (_temp, mut session) = open_session(&bytes, &tag);

                assert_eq!(
                    session.test_password(PASSWORD).expect("correct password"),
                    PasswordTest::Hit,
                    "{mode:?}/{compression:?} must accept the correct password"
                );
                assert_eq!(
                    session
                        .test_password(b"definitely-not-the-password")
                        .expect("wrong password"),
                    PasswordTest::Miss,
                    "{mode:?}/{compression:?} must reject a wrong password"
                );
            }
        }
    }

    #[test]
    fn aes_empty_password_is_miss() {
        let bytes = aes_zip(
            &[("hello.txt", HELLO)],
            CompressionMethod::Stored,
            AesMode::Aes256,
        );
        let (_temp, mut session) = open_session(&bytes, "aes-empty");

        assert_eq!(
            session.test_password(b"").expect("test password"),
            PasswordTest::Miss
        );
    }

    #[test]
    fn small_non_empty_aes_entry_is_ae2_and_verifies() {
        // The zip writer selects AE-2 for entries under 20 bytes and AE-1 for
        // larger ones. This covers the AE-2 non-empty path (CRC disabled).
        let bytes = aes_zip(
            &[("tiny.txt", b"tiny")],
            CompressionMethod::Stored,
            AesMode::Aes256,
        );
        let (_temp, mut session) = open_session(&bytes, "aes-ae2");

        assert_eq!(
            session.test_password(PASSWORD).expect("correct password"),
            PasswordTest::Hit
        );
        assert_eq!(
            session.test_password(b"wrong").expect("wrong password"),
            PasswordTest::Miss
        );
    }

    #[test]
    fn zero_length_aes_entry_can_be_verified() {
        // AES authenticates empty plaintext with an HMAC, so an all-empty AES
        // archive is safer to probe than the ZipCrypto equivalent.
        let bytes = aes_zip(
            &[("empty.txt", &[])],
            CompressionMethod::Stored,
            AesMode::Aes256,
        );
        let (_temp, mut session) = open_session(&bytes, "aes-zero-length");
        let selected = session
            .info()
            .selected_entry()
            .expect("zero-length AES entry must be selected");

        assert_eq!(session.info().encryption, Encryption::Aes);
        assert_eq!(selected.uncompressed_size, 0);
        assert_eq!(
            session.test_password(PASSWORD).expect("correct password"),
            PasswordTest::Hit
        );
        assert_eq!(
            session.test_password(b"wrong").expect("wrong password"),
            PasswordTest::Miss
        );
    }

    #[test]
    fn tampered_aes_authentication_code_is_miss() {
        for compression in [CompressionMethod::Stored, CompressionMethod::Deflated] {
            let mut bytes = aes_zip(&[("hello.txt", HELLO)], compression, AesMode::Aes256);
            let name_len = usize::from(u16::from_le_bytes([bytes[26], bytes[27]]));
            let extra_len = usize::from(u16::from_le_bytes([bytes[28], bytes[29]]));
            let compressed_size = u32::from_le_bytes(
                bytes[18..22]
                    .try_into()
                    .expect("local header compressed size"),
            ) as usize;
            let data_start = 30 + name_len + extra_len;
            let auth_code_last = data_start + compressed_size - 1;
            bytes[auth_code_last] ^= 0x01;

            let tag = format!("aes-tampered-{compression:?}");
            let (_temp, mut session) = open_session(&bytes, &tag);
            // The 2-byte verifier still matches, so only the HMAC can reject this.
            assert_eq!(
                session.test_password(PASSWORD).expect("tampered password"),
                PasswordTest::Miss,
                "{compression:?} tampered auth code must be rejected"
            );
        }
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
    fn factory_opens_independent_sessions() {
        let temp = TempArchive::new("factory");
        temp.write(&zipcrypto_zip());

        let factory = ZipFactory::new(temp.path().to_path_buf());
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

    #[test]
    fn zip_verifier_counts_fast_rejects_and_full_attempts() {
        let temp = TempArchive::new("zip-counters");
        temp.write(&zipcrypto_zip());
        let factory = ZipFactory::new(temp.path().to_path_buf());
        let mut session = factory.open().expect("session");

        for index in 0..20 {
            let candidate = format!("wrong-{index}");
            assert_eq!(
                session.test_password(candidate.as_bytes()).expect("miss"),
                PasswordTest::Miss
            );
        }
        assert_eq!(
            session.test_password(PASSWORD).expect("hit"),
            PasswordTest::Hit
        );

        let stats = factory.stats();
        assert_eq!(stats.fast_rejected, stats.by_filter.total());
        assert_eq!(stats.by_filter.zip_verifier, stats.fast_rejected);
        assert_eq!(FastFilterKind::ZipVerifier.as_str(), "zip_verifier");
        assert!(
            stats.fast_rejected >= 1 && stats.full_attempted >= 1,
            "verifier rejects and full checks must both be counted: {stats:?}"
        );
        // Every variant enters exactly one bucket: the 20 wrong candidates and
        // the correct candidate account for all 21 attempts.
        assert_eq!(stats.fast_rejected + stats.full_attempted, 21);
    }

    #[test]
    fn aes_verifier_counts_fast_rejects_and_full_attempts() {
        let bytes = aes_zip(
            &[("hello.txt", HELLO)],
            CompressionMethod::Stored,
            AesMode::Aes256,
        );
        let temp = TempArchive::new("aes-counters");
        temp.write(&bytes);
        let factory = ZipFactory::new(temp.path().to_path_buf());
        let mut session = factory.open().expect("session");

        for candidate in [b"wrong-a".as_slice(), b"wrong-b".as_slice()] {
            assert_eq!(
                session.test_password(candidate).expect("miss"),
                PasswordTest::Miss
            );
        }
        assert_eq!(
            session.test_password(PASSWORD).expect("hit"),
            PasswordTest::Hit
        );

        let stats = factory.stats();
        assert_eq!(stats.fast_rejected, stats.by_filter.total());
        assert_eq!(stats.by_filter.zip_verifier, stats.fast_rejected);
        assert_eq!(stats.fast_rejected + stats.full_attempted, 3);
    }
}
