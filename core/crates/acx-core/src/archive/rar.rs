// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

//! RAR engine backed by a user-installed `UnRAR.exe`.
//!
//! This is deliberately a whole-archive test: the UnRAR command line has no
//! multi-password session, and its listing output is localized, so parsing a
//! "smallest entry" is not reliable. W1-003 accepts the extra cost to keep the
//! correctness and licensing boundary simple. Clean-room header/KDF probes can
//! later reject most candidates before this process runs.

use super::info::{ArchiveFormat, ArchiveInfo, Encryption, PasswordTest};
use super::source::ArchiveSource;
use super::{ArchiveSession, ArchiveSessionFactory};
use crate::engines::external::{self, CancelToken, ExternalOutput, DEFAULT_TIMEOUT};
use crate::error::{AcxError, Result};
use std::ffi::OsString;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// One RAR session, owned by a scheduler worker.
pub struct RarSession {
    path: PathBuf,
    engine: PathBuf,
    info: ArchiveInfo,
    timeout: Duration,
    cancel: Option<CancelToken>,
}

impl RarSession {
    /// Open a RAR archive using a discovered user-installed engine.
    ///
    /// Split volumes are resolved first; UnRAR always receives the first volume.
    pub fn open(path: &Path) -> Result<Self> {
        let source = ArchiveSource::resolve(path)?;
        ensure_rar(source.format)?;
        ensure_complete_volumes(&source)?;
        let engine = external::find_unrar()?;
        let first = source.first_path().to_path_buf();
        let info = preflight(&first, source.format, &engine)?;
        Ok(Self::with_info(&first, engine, info))
    }

    /// Open with an explicit engine path (used by tests and diagnostics).
    pub fn open_with_engine(path: &Path, format: ArchiveFormat, engine: PathBuf) -> Result<Self> {
        ensure_rar(format)?;
        let info = preflight(path, format, &engine)?;
        Ok(Self::with_info(path, engine, info))
    }

    /// Build a session around metadata that is already known.
    fn with_info(path: &Path, engine: PathBuf, info: ArchiveInfo) -> Self {
        Self {
            path: path.to_path_buf(),
            engine,
            info,
            timeout: DEFAULT_TIMEOUT,
            cancel: None,
        }
    }

    /// Override the per-process timeout (useful for large local fixtures).
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

impl ArchiveSession for RarSession {
    fn info(&self) -> &ArchiveInfo {
        &self.info
    }

    fn test_password(&mut self, password: &[u8]) -> Result<PasswordTest> {
        if !self.info.whole_archive {
            return Err(AcxError::NotEncrypted);
        }

        // UnRAR's password prompt is line-oriented. A newline cannot be
        // represented through stdin; report it as a miss rather than silently
        // testing a truncated password.
        if password_has_line_break(password) {
            return Ok(PasswordTest::Miss);
        }

        let encoded = external::encode_password(password)?;
        let output = external::run_cancellable(
            &self.engine,
            test_args(&self.path),
            Some(encoded.as_ref()),
            self.timeout,
            self.cancel.as_ref(),
        )?;
        if output.cancelled {
            return Err(AcxError::Cancelled);
        }
        if output.timed_out {
            return Err(AcxError::External(format!(
                "UnRAR timed out after {:?} while testing a candidate",
                self.timeout
            )));
        }
        if let Some(volume) = missing_volume_message(&output) {
            return Err(AcxError::MissingVolume(volume));
        }

        match classify_test_exit(self.info.format, output.code) {
            Some(result) => Ok(result),
            None => Err(engine_failure("test", &output)),
        }
    }

    fn set_cancel_token(&mut self, token: CancelToken) {
        self.cancel = Some(token);
    }
}

/// Opens a fresh [`RarSession`] per scheduler worker.
///
/// The archive is probed once, when the factory is created, and every worker
/// reuses that metadata. Probing inside `open()` would start `unrar t -p-`
/// (and `l -p-` for encrypted archives) once per worker, adding about `2N`
/// engine processes before `-t N` tests any candidate.
#[derive(Debug)]
pub struct RarFactory {
    /// Archive path. Changing it after construction leaves `info` stale; create
    /// a new factory instead.
    pub path: PathBuf,
    engine: PathBuf,
    info: ArchiveInfo,
}

impl RarFactory {
    /// Discover the user-installed engine and probe the archive once.
    pub fn new(path: PathBuf) -> Result<Self> {
        let source = ArchiveSource::resolve(&path)?;
        ensure_rar(source.format)?;
        ensure_complete_volumes(&source)?;
        let engine = external::find_unrar()?;
        let first = source.first_path().to_path_buf();
        let info = preflight(&first, source.format, &engine)?;
        Ok(Self::with_cached_info(first, engine, info))
    }

    /// Explicit engine path; still probes the archive once.
    pub fn with_engine(path: PathBuf, engine: PathBuf) -> Result<Self> {
        let source = ArchiveSource::resolve(&path)?;
        ensure_rar(source.format)?;
        ensure_complete_volumes(&source)?;
        let first = source.first_path().to_path_buf();
        let info = preflight(&first, source.format, &engine)?;
        Ok(Self::with_cached_info(first, engine, info))
    }

    /// Reuse metadata returned by [`super::preflight`] without probing again.
    ///
    /// The CLI already probes to print the archive summary; this constructor
    /// keeps that single probe instead of paying for a second one. The metadata
    /// must have been produced for `path`; a mismatch is rejected so a stale
    /// `whole_archive` flag cannot turn an unencrypted archive into a hit.
    pub fn from_info(path: PathBuf, info: ArchiveInfo) -> Result<Self> {
        ensure_rar(info.format)?;
        let source = match ArchiveSource::resolve(&path) {
            Ok(source) => source,
            Err(_) if !same_archive(&path, &info.path) => {
                return Err(AcxError::Unsupported(
                    "cached RAR metadata belongs to a different archive".to_string(),
                ));
            }
            Err(error) => return Err(error),
        };
        ensure_rar(source.format)?;
        ensure_complete_volumes(&source)?;
        let first = source.first_path().to_path_buf();
        if !same_archive(&first, &info.path) {
            return Err(AcxError::Unsupported(
                "cached RAR metadata belongs to a different archive".to_string(),
            ));
        }
        let engine = external::find_unrar()?;
        Ok(Self::with_cached_info(first, engine, info))
    }

    /// Build a factory around already-probed metadata.
    ///
    /// No engine process is started here or in [`ArchiveSessionFactory::open`].
    /// The caller is responsible for passing metadata produced for `path`, and
    /// must not modify the archive while this factory is in use: the metadata
    /// is a snapshot, not a live view.
    fn with_cached_info(path: PathBuf, engine: PathBuf, info: ArchiveInfo) -> Self {
        Self { path, engine, info }
    }

    /// Metadata probed when this factory was created.
    pub fn info(&self) -> &ArchiveInfo {
        &self.info
    }
}

impl ArchiveSessionFactory for RarFactory {
    fn open(&self) -> Result<Box<dyn ArchiveSession>> {
        // Clone cached metadata only: opening a worker must not start UnRAR.
        Ok(Box::new(RarSession::with_info(
            &self.path,
            self.engine.clone(),
            self.info.clone(),
        )))
    }
}

/// Compare two paths, resolving them when possible so `.\a.rar` and `a.rar`
/// are recognized as the same archive on Windows.
fn same_archive(left: &Path, right: &Path) -> bool {
    if left == right {
        return true;
    }
    match (std::fs::canonicalize(left), std::fs::canonicalize(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

/// Reject a RAR volume set whose named next part is absent and whose main
/// header says it is a multi-volume archive. UnRAR would otherwise open the
/// first volume and only fail while testing a candidate.
fn ensure_complete_volumes(source: &ArchiveSource) -> Result<()> {
    // A single `.part1.rar` with a volume flag is the unambiguous case: the
    // archive says another part exists, but none is present. For multi-part
    // sets we let UnRAR report the exact missing volume; size heuristics would
    // misclassify a complete set whose last part happens to be full-size.
    if source.parts.len() != 1 {
        return Ok(());
    }
    let Some(next) = source.missing_next_part() else {
        return Ok(());
    };
    if rar_volume_flag(source.first_path(), source.format)? {
        return Err(AcxError::MissingVolume(next.display().to_string()));
    }
    Ok(())
}

fn rar_volume_flag(path: &Path, format: ArchiveFormat) -> Result<bool> {
    let mut file = File::open(path)?;
    let mut head = [0u8; 32];
    let mut filled = 0;
    while filled < head.len() {
        match file.read(&mut head[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) => return Err(AcxError::Io(error)),
        }
    }
    let head = &head[..filled];

    match format {
        ArchiveFormat::Rar4 => {
            if head.len() < 12 || !head.starts_with(b"Rar!\x1a\x07\x00") || head[9] != 0x73 {
                return Ok(false);
            }
            let flags = u16::from_le_bytes([head[10], head[11]]);
            Ok(flags & 0x0001 != 0)
        }
        ArchiveFormat::Rar5 => {
            if head.len() < 16 || !head.starts_with(b"Rar!\x1a\x07\x01\x00") {
                return Ok(false);
            }
            let mut offset = 12;
            let Some(_header_size) = read_vint(head, &mut offset) else {
                return Ok(false);
            };
            let Some(header_type) = read_vint(head, &mut offset) else {
                return Ok(false);
            };
            if header_type != 1 {
                return Ok(false);
            }
            // RAR5 main header: header flags, optional extra/data sizes, then
            // archive flags (where MHFL_VOLUME lives).
            let Some(header_flags) = read_vint(head, &mut offset) else {
                return Ok(false);
            };
            if header_flags & 0x0001 != 0 {
                let Some(_extra_size) = read_vint(head, &mut offset) else {
                    return Ok(false);
                };
            }
            if header_flags & 0x0002 != 0 {
                let Some(_data_size) = read_vint(head, &mut offset) else {
                    return Ok(false);
                };
            }
            let Some(archive_flags) = read_vint(head, &mut offset) else {
                return Ok(false);
            };
            Ok(archive_flags & 0x0001 != 0)
        }
        _ => Ok(false),
    }
}

fn read_vint(data: &[u8], offset: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    let mut shift = 0u32;
    loop {
        let byte = *data.get(*offset)?;
        *offset += 1;
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

/// Reject non-RAR formats before starting an external process.
fn ensure_rar(format: ArchiveFormat) -> Result<()> {
    if matches!(format, ArchiveFormat::Rar4 | ArchiveFormat::Rar5) {
        Ok(())
    } else {
        Err(AcxError::Unsupported(format!(
            "not a RAR archive (format {})",
            format.as_str()
        )))
    }
}

/// Classify one candidate-test exit code for the archive format.
///
/// RAR5 reports a wrong password as 11. RAR4 reports the same condition as 3
/// ("checksum error in the encrypted file"), so 3 is a miss only for RAR4;
/// for RAR5 it remains an external error because it usually means corruption.
fn classify_test_exit(format: ArchiveFormat, code: Option<i32>) -> Option<PasswordTest> {
    match code {
        Some(0) => Some(PasswordTest::Hit),
        Some(11) => Some(PasswordTest::Miss),
        Some(3) if format == ArchiveFormat::Rar4 => Some(PasswordTest::Miss),
        _ => None,
    }
}

/// Probe exit codes and determine whether the archive is encrypted.
fn preflight(path: &Path, format: ArchiveFormat, engine: &Path) -> Result<ArchiveInfo> {
    let test = external::run(engine, preflight_args(path), None, DEFAULT_TIMEOUT)?;
    if test.timed_out {
        return Err(AcxError::External(format!(
            "UnRAR preflight timed out after {:?}",
            DEFAULT_TIMEOUT
        )));
    }
    if let Some(volume) = missing_volume_message(&test) {
        return Err(AcxError::MissingVolume(volume));
    }

    match test.code {
        Some(0) => Ok(ArchiveInfo {
            path: path.to_path_buf(),
            format,
            encryption: Encryption::None,
            selected: None,
            whole_archive: false,
            header_encrypted: false,
            entries: Vec::new(),
        }),
        Some(11) => {
            // Encrypted. `l -p-` succeeds for file-encrypted headers and fails
            // for header-encrypted archives; both are tested the same way, but
            // the distinction is useful in diagnostics.
            let listing = external::run(engine, listing_args(path), None, DEFAULT_TIMEOUT)?;
            if listing.timed_out {
                return Err(AcxError::External(format!(
                    "UnRAR listing timed out after {:?}",
                    DEFAULT_TIMEOUT
                )));
            }
            match listing.code {
                Some(0) | Some(11) => Ok(encrypted_info(path, format)),
                _ => Err(engine_failure("listing", &listing)),
            }
        }
        Some(3) if format == ArchiveFormat::Rar4 => {
            // RAR4 uses exit 3 for a missing/wrong password. A successful
            // listing then marks encrypted entries with `*`; a failed listing
            // is only trusted as header encryption when the RAR4 main-header
            // flag says so. Otherwise the archive is damaged, not encrypted.
            let listing = external::run(engine, listing_args(path), None, DEFAULT_TIMEOUT)?;
            if listing.timed_out {
                return Err(AcxError::External(format!(
                    "UnRAR listing timed out after {:?}",
                    DEFAULT_TIMEOUT
                )));
            }
            match listing.code {
                Some(3) if rar4_header_encrypted(path)? => Ok(encrypted_info(path, format)),
                Some(0) if listing_marks_encrypted(&listing.stdout) => {
                    Ok(encrypted_info(path, format))
                }
                Some(0) => Err(engine_failure("preflight", &test)),
                _ => Err(engine_failure("listing", &listing)),
            }
        }
        _ => Err(engine_failure("preflight", &test)),
    }
}

/// RAR4 main-header flag for encrypted headers (`MHD_PASSWORD`).
const RAR4_MAIN_HEADER_ENCRYPTED: u16 = 0x0080;

/// Read the unencrypted RAR4 main header and check its header-encryption flag.
///
/// RAR4 writes the marker, block CRC, block type, and flags before encrypting
/// the rest of the header, so these 12 bytes remain readable even for `-hp`.
fn rar4_header_encrypted(path: &Path) -> Result<bool> {
    let mut file = std::fs::File::open(path)?;
    let mut header = [0u8; 12];
    file.read_exact(&mut header)?;
    Ok(rar4_header_is_encrypted(&header))
}

fn rar4_header_is_encrypted(header: &[u8]) -> bool {
    if header.len() < 12 || !header.starts_with(b"Rar!\x1a\x07\x00") || header[9] != 0x73 {
        return false;
    }
    let flags = u16::from_le_bytes([header[10], header[11]]);
    flags & RAR4_MAIN_HEADER_ENCRYPTED != 0
}

fn encrypted_info(path: &Path, format: ArchiveFormat) -> ArchiveInfo {
    ArchiveInfo {
        path: path.to_path_buf(),
        format,
        encryption: Encryption::Rar,
        selected: None,
        whole_archive: true,
        header_encrypted: false,
        entries: Vec::new(),
    }
}

/// RAR's console listing prefixes encrypted entries with `*`.
///
/// This is only used to tell RAR4's exit-3 "wrong password" apart from a
/// corrupt but unencrypted archive; sizes, dates, and names are still not
/// parsed from the localized listing.
fn listing_marks_encrypted(stdout: &[u8]) -> bool {
    stdout
        .split(|byte| *byte == b'\n')
        .any(|line| line.starts_with(b"*"))
}

fn preflight_args(path: &Path) -> Vec<OsString> {
    vec![
        "t".into(),
        "-cfg-".into(),
        "-c-".into(),
        "-idq".into(),
        "-p-".into(),
        command_path(path).into_os_string(),
    ]
}

fn listing_args(path: &Path) -> Vec<OsString> {
    // `-idq` suppresses `l` output entirely, including the `*` marker that
    // distinguishes an encrypted RAR4 entry from a corrupt archive.
    vec![
        "l".into(),
        "-cfg-".into(),
        "-c-".into(),
        "-p-".into(),
        command_path(path).into_os_string(),
    ]
}

fn test_args(path: &Path) -> Vec<OsString> {
    vec![
        "t".into(),
        "-cfg-".into(),
        "-c-".into(),
        "-idq".into(),
        "-p".into(),
        command_path(path).into_os_string(),
    ]
}

/// UnRAR parses a leading `-` as a switch and has no `--` escape. Resolve the
/// archive to an absolute path so a file such as `-archive.rar` is still data.
fn command_path(path: &Path) -> PathBuf {
    std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf())
}

fn password_has_line_break(password: &[u8]) -> bool {
    password.iter().any(|byte| *byte == b'\n' || *byte == b'\r')
}

/// Extract UnRAR's missing-volume path from its diagnostic output.
///
/// UnRAR writes this line in English for the shipped Windows build. The
/// Chinese literal is kept as a fallback; an unrecognized locale simply falls
/// back to the generic external error.
fn missing_volume_message(output: &ExternalOutput) -> Option<String> {
    for bytes in [&output.stderr, &output.stdout] {
        let text = String::from_utf8_lossy(bytes);
        for line in text.lines() {
            let lower = line.to_ascii_lowercase();
            if let Some(position) = lower.find("cannot find volume") {
                let path = line[position + "cannot find volume".len()..].trim();
                let path = path.trim_start_matches([':', ' ']);
                if !path.is_empty() {
                    return Some(path.to_string());
                }
            }
            if line.contains("找不到卷") || line.contains("缺少卷") {
                return Some(line.trim().to_string());
            }
        }
    }
    None
}

/// Normalize an unexpected external exit into an actionable error.
fn engine_failure(action: &str, output: &ExternalOutput) -> AcxError {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let detail = stderr.trim();
    let detail = if detail.is_empty() {
        String::new()
    } else {
        format!(": {detail}")
    };
    AcxError::External(format!(
        "UnRAR {action} failed with exit code {}{detail}",
        output
            .code
            .map_or_else(|| "unknown".to_string(), |code| code.to_string())
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preflight_arguments_never_contain_a_password() {
        let args = preflight_args(Path::new("archive.rar"));
        assert!(args
            .iter()
            .all(|arg| !arg.to_string_lossy().contains("P@ss")));
        assert!(args.iter().any(|arg| arg == "-p-"));
    }

    #[test]
    fn test_arguments_prompt_instead_of_embedding_password() {
        let args = test_args(Path::new("archive.rar"));
        assert!(args.iter().any(|arg| arg == "-p"));
        assert!(args
            .iter()
            .all(|arg| !arg.to_string_lossy().contains("P@ss")));
    }

    #[test]
    fn archive_path_is_made_absolute_to_avoid_switch_parsing() {
        let path = command_path(Path::new("-archive.rar"));
        assert!(path.is_absolute());
        assert!(!path.to_string_lossy().starts_with('-'));
    }

    #[test]
    fn newline_password_is_detected() {
        assert!(password_has_line_break(b"abc\ndef"));
        assert!(password_has_line_break(b"abc\rdef"));
        assert!(!password_has_line_break(b"normal"));
    }

    #[test]
    fn rar4_wrong_password_exit_is_a_miss() {
        assert_eq!(
            classify_test_exit(ArchiveFormat::Rar4, Some(3)),
            Some(PasswordTest::Miss)
        );
        assert_eq!(
            classify_test_exit(ArchiveFormat::Rar4, Some(0)),
            Some(PasswordTest::Hit)
        );
        assert_eq!(
            classify_test_exit(ArchiveFormat::Rar5, Some(11)),
            Some(PasswordTest::Miss)
        );
    }

    #[test]
    fn rar5_corrupt_archive_exit_is_not_a_miss() {
        assert_eq!(classify_test_exit(ArchiveFormat::Rar5, Some(3)), None);
    }

    #[test]
    fn rar4_main_header_flag_detects_header_encryption() {
        let mut header = [0u8; 12];
        header[..7].copy_from_slice(b"Rar!\x1a\x07\x00");
        header[9] = 0x73;
        assert!(!rar4_header_is_encrypted(&header));

        header[10] = 0x80;
        assert!(rar4_header_is_encrypted(&header));

        let mut rar5 = [0u8; 12];
        rar5[..8].copy_from_slice(b"Rar!\x1a\x07\x01\x00");
        rar5[9] = 0x73;
        assert!(!rar4_header_is_encrypted(&rar5));
        assert!(!rar4_header_is_encrypted(&[]));
    }

    #[test]
    fn listing_marker_identifies_encrypted_rar4_entries() {
        assert!(listing_marks_encrypted(
            b" Attributes      Size     Date    Time   Name\n\
              *   I.A....        24  2026-11-24 22:29  hello.txt\n"
        ));
        assert!(!listing_marks_encrypted(
            b" Attributes      Size     Date    Time   Name\n\
                  I.A....        24  2026-11-24 22:29  hello.txt\n"
        ));
    }

    #[test]
    fn factory_open_reuses_cached_info_without_starting_the_engine() {
        let info = ArchiveInfo {
            path: PathBuf::from("archive.rar"),
            format: ArchiveFormat::Rar5,
            encryption: Encryption::Rar,
            selected: None,
            whole_archive: true,
            header_encrypted: false,
            entries: Vec::new(),
        };
        let factory = RarFactory::with_cached_info(
            PathBuf::from("archive.rar"),
            PathBuf::from("definitely-not-an-unrar-binary"),
            info,
        );

        // Opening a worker must only clone the cached metadata. A missing
        // engine would surface here if `open` still ran the preflight.
        let first = factory.open().expect("cached open");
        let second = factory.open().expect("cached open");
        assert_eq!(first.info().format, ArchiveFormat::Rar5);
        assert_eq!(first.info().encryption, Encryption::Rar);
        assert!(first.info().whole_archive);
        assert_eq!(second.info().format, ArchiveFormat::Rar5);
        assert_eq!(factory.info().format, ArchiveFormat::Rar5);
    }

    #[test]
    fn from_info_rejects_non_rar_metadata_before_probing() {
        let info = ArchiveInfo {
            path: PathBuf::from("archive.zip"),
            format: ArchiveFormat::Zip,
            encryption: Encryption::ZipCrypto,
            selected: Some(0),
            whole_archive: false,
            header_encrypted: false,
            entries: Vec::new(),
        };
        let error = RarFactory::from_info(PathBuf::from("archive.zip"), info)
            .expect_err("ZIP metadata must be rejected");
        assert!(matches!(error, AcxError::Unsupported(_)));
    }

    #[test]
    fn from_info_rejects_metadata_for_a_different_archive() {
        let info = ArchiveInfo {
            path: PathBuf::from("one.rar"),
            format: ArchiveFormat::Rar5,
            encryption: Encryption::Rar,
            selected: None,
            whole_archive: true,
            header_encrypted: false,
            entries: Vec::new(),
        };
        let error = RarFactory::from_info(PathBuf::from("two.rar"), info)
            .expect_err("metadata for another archive must be rejected");
        assert!(matches!(error, AcxError::Unsupported(_)));
    }

    #[test]
    fn rar5_volume_flag_reads_archive_flags_not_header_flags() {
        // RAR5 main header: size(vint), type=1, header flags=0x05 (extra area),
        // extra size=7, then archive flags. Only the archive flag 0x0001 means
        // the archive is part of a multi-volume set.
        let mut header = [0u8; 32];
        header[..8].copy_from_slice(b"Rar!\x1a\x07\x01\x00");
        header[12] = 0x05; // header size (value irrelevant here)
        header[13] = 0x01; // main header type
        header[14] = 0x05; // common header flags: extra area + unknown-skip
        header[15] = 0x07; // extra area size
        header[16] = 0x00; // archive flags: single volume
        let path = temp_header("rar5-single", &header);
        assert!(!rar_volume_flag(&path, ArchiveFormat::Rar5).expect("parse"));
        std::fs::write(&path, {
            let mut split = header;
            split[16] = 0x01; // MHFL_VOLUME in archive flags
            split
        })
        .expect("write split header");
        assert!(rar_volume_flag(&path, ArchiveFormat::Rar5).expect("parse"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn rar4_volume_flag_is_read() {
        let mut header = [0u8; 12];
        header[..7].copy_from_slice(b"Rar!\x1a\x07\x00");
        header[9] = 0x73; // main header
        header[10] = 0x00;
        let path = temp_header("rar4-single", &header);
        assert!(!rar_volume_flag(&path, ArchiveFormat::Rar4).expect("parse"));
        header[10] = 0x01; // MHD_VOLUME
        std::fs::write(&path, header).expect("write volume header");
        assert!(rar_volume_flag(&path, ArchiveFormat::Rar4).expect("parse"));
        let _ = std::fs::remove_file(path);
    }

    fn temp_header(tag: &str, bytes: &[u8]) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or(0);
        let mut dir = std::env::current_exe().unwrap_or_default();
        if dir.pop() {
            dir.pop();
        }
        dir.push("acx-test-tmp");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join(format!(
            "acx-rar-header-{tag}-{}-{nanos}.bin",
            std::process::id()
        ));
        std::fs::write(&path, bytes).expect("write header fixture");
        path
    }

    #[test]
    fn missing_engine_is_an_external_error() {
        let error = match RarSession::open_with_engine(
            Path::new("missing.rar"),
            ArchiveFormat::Rar5,
            PathBuf::from("definitely-not-an-unrar-binary"),
        ) {
            Ok(_) => panic!("missing engine must fail"),
            Err(error) => error,
        };
        assert!(matches!(error, AcxError::External(_)));
    }
}
