// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

//! Archive source resolution: split volumes and SFX payload offsets.
//!
//! Engines see a single logical byte stream. For 7-Zip/ ZIP byte-split volumes
//! (`.001`, `.0001`) that stream is the concatenation of the parts; for an SFX
//! executable the stream starts at the archive payload, after the PE stub.
//! RAR is different: external UnRAR opens the first volume itself, so this
//! module only validates the volume set and returns its first path.

use super::detect_magic;
use super::info::ArchiveFormat;
use crate::error::{AcxError, Result};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// SFX stubs are normally well under 1 MiB. The cap keeps a malformed PE from
/// turning format detection into a full-file scan.
const MAX_SFX_SCAN_BYTES: u64 = 32 * 1024 * 1024;

/// How far past a missing numeric part we look for evidence of a gap.
const MISSING_VOLUME_LOOKAHEAD: u64 = 1000;

/// A logical archive: format, ordered byte-split parts, and SFX payload offset.
#[derive(Debug, Clone)]
pub struct ArchiveSource {
    pub format: ArchiveFormat,
    pub parts: Vec<PathBuf>,
    /// Offset inside `parts[0]` where the archive byte stream begins.
    pub start_offset: u64,
}

impl ArchiveSource {
    /// Detect the format and resolve the complete, contiguous volume set.
    ///
    /// A missing part is reported before any engine or dictionary work starts.
    pub fn resolve(path: &Path) -> Result<Self> {
        if let Some(name) = path.file_name().and_then(|name| name.to_str()) {
            if is_pkzip_spanned(name) {
                return Err(AcxError::Unsupported(format!(
                    "PKZIP spanned archives (.z01/.z02) are not supported yet: {}",
                    path.display()
                )));
            }
        }
        let hint = first_part_hint(path);
        let (format, start_offset, parts) = match hint {
            Some(hint) if hint.exists() => {
                let (format, start_offset) = detect_archive_format(&hint)?;
                let parts = discover_parts(path, format, start_offset)?;
                (format, start_offset, parts)
            }
            Some(hint) => {
                // A `.partN.rar` name is a strong split-volume signal: even a
                // continuation segment carries a RAR header, so do not mistake
                // it for a single archive when part 1 is absent.
                if let Some(name) = path.file_name().and_then(|name| name.to_str()) {
                    if is_rar_part_name(name) {
                        return Err(AcxError::MissingVolume(display(&hint)));
                    }
                }
                // The first part is absent. A complete archive can still have a
                // name that looks like a continuation (e.g. `movie.r01` or a
                // numeric extension); try the named file as a single archive
                // before reporting the hinted part as missing.
                match detect_archive_format(path) {
                    Ok((format, start_offset)) => (format, start_offset, vec![path.to_path_buf()]),
                    Err(_) => return Err(AcxError::MissingVolume(display(&hint))),
                }
            }
            None => {
                let (format, start_offset) = detect_archive_format(path)?;
                let parts = discover_parts(path, format, start_offset)?;
                (format, start_offset, parts)
            }
        };
        Ok(Self {
            format,
            parts,
            start_offset,
        })
    }

    /// Open a fresh logical reader. Every scheduler worker gets its own file
    /// handles so seeks never race.
    pub fn reader(&self) -> Result<VolumeReader> {
        VolumeReader::open(&self.parts, self.start_offset)
    }

    /// First physical part. For RAR this is the path passed to UnRAR.
    pub fn first_path(&self) -> &Path {
        &self.parts[0]
    }

    /// Convert a truncated-archive classification into a missing-volume error
    /// when the naming scheme implies another part.
    pub fn classify_incomplete(&self, error: AcxError) -> AcxError {
        match error {
            AcxError::Truncated(message) => match self.missing_next_part() {
                Some(next) => AcxError::MissingVolume(display(&next)),
                None => AcxError::Truncated(message),
            },
            other => other,
        }
    }

    /// The next part implied by the volume naming scheme, even though it is
    /// absent. Used to turn an incomplete header into "missing volume N"
    /// instead of a generic truncation error.
    pub fn missing_next_part(&self) -> Option<PathBuf> {
        let next = self.next_part_name()?;
        // A single `.001` part is either a complete archive with an unusual
        // name or the first part of a split set. Only report the next part as
        // missing when the last present part looks like a full-size volume.
        if self.parts.len() == 1 {
            return Some(next);
        }
        let last = std::fs::metadata(self.parts.last()?).ok()?.len();
        let previous = std::fs::metadata(&self.parts[self.parts.len() - 2])
            .ok()?
            .len();
        (last > 0 && last == previous).then_some(next)
    }

    fn next_part_name(&self) -> Option<PathBuf> {
        let first = self.parts.first()?;
        let name = first.file_name()?.to_str()?;
        let lower = name.to_ascii_lowercase();

        if let Some(part_pos) = lower.rfind(".part") {
            let tail = &name[part_pos + ".part".len()..];
            if let Some(digits) = tail.strip_suffix(".rar") {
                if !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()) {
                    let width = digits.len();
                    let base = &name[..part_pos + ".part".len()];
                    return Some(
                        first.with_file_name(format!("{base}{:0width$}.rar", self.parts.len() + 1)),
                    );
                }
            }
        }

        if let Some((base, _)) = self
            .parts
            .last()
            .and_then(|part| part.file_name())
            .and_then(|name| name.to_str())
            .and_then(split_old_rar)
        {
            return Some(
                first.with_file_name(format!("{base}.r{:02}", self.parts.len().saturating_sub(1))),
            );
        }

        if let Some((base, width)) = numeric_split(name) {
            return Some(first.with_file_name(format!("{base}.{:0width$}", self.parts.len() + 1)));
        }

        None
    }
}

/// Detect the archive format, looking through a PE/SFX stub when present.
pub(crate) fn detect_archive_format(path: &Path) -> Result<(ArchiveFormat, u64)> {
    let mut file = File::open(path)?;
    let mut head = [0u8; 8];
    let filled = read_up_to(&mut file, &mut head)?;
    if filled >= 2 && &head[..2] == b"MZ" {
        let (offset, format) = find_sfx_payload(&mut file, path)?;
        return Ok((format, offset));
    }
    let format = detect_magic(&head[..filled])?;
    Ok((format, 0))
}

fn read_up_to(file: &mut File, buf: &mut [u8]) -> Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match file.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) => return Err(AcxError::Io(error)),
        }
    }
    Ok(filled)
}

/// Find the first supported archive signature after an `MZ` stub.
fn find_sfx_payload(file: &mut File, path: &Path) -> Result<(u64, ArchiveFormat)> {
    file.seek(SeekFrom::Start(0))?;
    let length = file.metadata()?.len();
    let limit = length.min(MAX_SFX_SCAN_BYTES);
    let mut data = Vec::with_capacity(limit as usize);
    let mut limited = file.take(limit);
    limited.read_to_end(&mut data)?;

    for offset in 2..data.len() {
        if let Ok(format) = detect_magic(&data[offset..]) {
            return Ok((offset as u64, format));
        }
    }
    Err(AcxError::Unsupported(format!(
        "PE/SFX file {} has no supported archive payload in its first {} bytes",
        path.display(),
        limit
    )))
}

/// If `path` names a continuation part, return the first part.
fn first_part_hint(path: &Path) -> Option<PathBuf> {
    let name = path.file_name()?.to_str()?;
    let lower = name.to_ascii_lowercase();

    if let Some(part_pos) = lower.rfind(".part") {
        let tail = &name[part_pos + ".part".len()..];
        if let Some(digits) = tail.strip_suffix(".rar") {
            if !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()) {
                let width = digits.len();
                let base = &name[..part_pos + ".part".len()];
                return Some(path.with_file_name(format!("{base}{:0width$}.rar", 1)));
            }
        }
    }

    if let Some((base, _)) = split_old_rar(name) {
        return Some(path.with_file_name(format!("{base}.rar")));
    }

    if let Some((base, width)) = numeric_split(name) {
        return Some(path.with_file_name(format!("{base}.{:0width$}", 1)));
    }

    None
}

/// Resolve split-volume names. Returns a single part when no split pattern
/// matches.
fn discover_parts(path: &Path, format: ArchiveFormat, _start_offset: u64) -> Result<Vec<PathBuf>> {
    let name = match path.file_name().and_then(|name| name.to_str()) {
        Some(name) => name,
        // A non-UTF-8 file name cannot be matched against volume patterns.
        None => return Ok(vec![path.to_path_buf()]),
    };

    if format == ArchiveFormat::Zip && is_pkzip_spanned(name) {
        return Err(AcxError::Unsupported(format!(
            "PKZIP spanned archives (.z01/.z02) are not supported yet: {}",
            path.display()
        )));
    }

    if matches!(format, ArchiveFormat::Rar4 | ArchiveFormat::Rar5) {
        if let Some(parts) = rar_parts(path, name) {
            return parts;
        }
    }

    if let Some((base, width)) = numeric_split(name) {
        return collect_contiguous(
            move |index| path.with_file_name(format!("{base}.{index:0width$}")),
            1,
        );
    }

    Ok(vec![path.to_path_buf()])
}

fn is_pkzip_spanned(name: &str) -> bool {
    let Some((_, suffix)) = name.rsplit_once('.') else {
        return false;
    };
    let lower = suffix.to_ascii_lowercase();
    let Some(digits) = lower.strip_prefix('z') else {
        return false;
    };
    !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
}

/// Return `(base, width)` for `name.001` / `name.0001`.
fn numeric_split(name: &str) -> Option<(&str, usize)> {
    let (base, suffix) = name.rsplit_once('.')?;
    // Require a leading zero: `.001`/`.0001` are volume suffixes, while a
    // complete archive such as `movie.2024` must stay a single file.
    if suffix.len() < 3
        || !suffix.starts_with('0')
        || !suffix.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    Some((base, suffix.len()))
}

/// Whether `name` is `base.partN.rar` (the strong RAR volume convention).
fn is_rar_part_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    let Some(part_pos) = lower.rfind(".part") else {
        return false;
    };
    let tail = &name[part_pos + ".part".len()..];
    tail.strip_suffix(".rar").is_some_and(|digits| {
        !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
    })
}

/// RAR `.partN.rar` and old `.rar` + `.r00` volume sets.
fn rar_parts(path: &Path, name: &str) -> Option<Result<Vec<PathBuf>>> {
    let lower = name.to_ascii_lowercase();

    if let Some(part_pos) = lower.rfind(".part") {
        let tail = &name[part_pos + ".part".len()..];
        let digits = tail.strip_suffix(".rar")?;
        if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        let width = digits.len();
        let base = &name[..part_pos + ".part".len()];
        return Some(collect_contiguous(
            move |index| path.with_file_name(format!("{base}{index:0width$}.rar")),
            1,
        ));
    }

    // Old style: movie.rar, movie.r00, movie.r01, ...
    if let Some((base, _)) = split_old_rar(name) {
        let first = path.with_file_name(format!("{base}.rar"));
        if !first.exists() {
            return Some(Err(AcxError::MissingVolume(display(&first))));
        }
        let rest = match collect_contiguous(
            move |index| path.with_file_name(format!("{base}.r{index:02}")),
            0,
        ) {
            Ok(parts) => parts,
            Err(error) => return Some(Err(error)),
        };
        let mut parts = Vec::with_capacity(rest.len() + 1);
        parts.push(first);
        parts.extend(rest);
        return Some(Ok(parts));
    }

    if lower.ends_with(".rar") {
        let base = &name[..name.len() - ".rar".len()];
        let r00 = path.with_file_name(format!("{base}.r00"));
        if r00.exists() {
            let rest = match collect_contiguous(
                move |index| path.with_file_name(format!("{base}.r{index:02}")),
                0,
            ) {
                Ok(parts) => parts,
                Err(error) => return Some(Err(error)),
            };
            let mut parts = Vec::with_capacity(rest.len() + 1);
            parts.push(path.to_path_buf());
            parts.extend(rest);
            return Some(Ok(parts));
        }
    }

    None
}

/// `movie.r00` -> `("movie", 0)`; only 2+ digits after `r`.
fn split_old_rar(name: &str) -> Option<(&str, u64)> {
    let (base, suffix) = name.rsplit_once('.')?;
    let lower = suffix.to_ascii_lowercase();
    let digits = lower.strip_prefix('r')?;
    if digits.len() < 2 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let number = digits.parse::<u64>().ok()?;
    Some((base, number))
}

/// Collect `candidate(1..n)` until the first gap, then report the gap if a
/// later part exists. This is what turns "not found" into "missing volume 004".
fn collect_contiguous<F>(mut candidate: F, start: u64) -> Result<Vec<PathBuf>>
where
    F: FnMut(u64) -> PathBuf,
{
    let mut parts = Vec::new();
    let mut index = start;
    loop {
        let part = candidate(index);
        if !part.exists() {
            break;
        }
        parts.push(part);
        index += 1;
    }

    let missing = candidate(index);
    if collect_gap_exists(&mut candidate, index + 1) {
        return Err(AcxError::MissingVolume(display(&missing)));
    }
    if parts.is_empty() {
        return Err(AcxError::MissingVolume(display(&missing)));
    }
    Ok(parts)
}

fn collect_gap_exists<F>(candidate: &mut F, start: u64) -> bool
where
    F: FnMut(u64) -> PathBuf,
{
    for index in start..start.saturating_add(MISSING_VOLUME_LOOKAHEAD) {
        if candidate(index).exists() {
            return true;
        }
    }
    false
}

fn display(path: &Path) -> String {
    path.display().to_string()
}

/// A `Read + Seek` view over concatenated volume parts.
///
/// Logical offset 0 is `start_offset` inside the first part. All other parts
/// are appended in order.
#[derive(Debug)]
pub struct VolumeReader {
    files: Vec<File>,
    lengths: Vec<u64>,
    start_offset: u64,
    /// Bytes available in the first part after `start_offset`.
    first_len: u64,
    total: u64,
    position: u64,
}

impl VolumeReader {
    pub fn open(parts: &[PathBuf], start_offset: u64) -> Result<Self> {
        if parts.is_empty() {
            return Err(AcxError::Internal(
                "archive source has no volume parts".to_string(),
            ));
        }
        let mut files = Vec::with_capacity(parts.len());
        let mut lengths = Vec::with_capacity(parts.len());
        for part in parts {
            let file = File::open(part)?;
            let length = file.metadata()?.len();
            files.push(file);
            lengths.push(length);
        }
        if start_offset > lengths[0] {
            return Err(AcxError::Corrupt(format!(
                "SFX payload offset {start_offset} is past the end of {}",
                parts[0].display()
            )));
        }
        let first_len = lengths[0] - start_offset;
        let total = first_len
            .checked_add(lengths[1..].iter().sum::<u64>())
            .ok_or_else(|| AcxError::Corrupt("archive volume set is too large".to_string()))?;
        Ok(Self {
            files,
            lengths,
            start_offset,
            first_len,
            total,
            position: 0,
        })
    }

    fn locate(&self, position: u64) -> Option<(usize, u64)> {
        if position < self.first_len {
            return Some((0, self.start_offset + position));
        }
        let mut remaining = position - self.first_len;
        for (index, &length) in self.lengths.iter().enumerate().skip(1) {
            if remaining < length {
                return Some((index, remaining));
            }
            remaining -= length;
        }
        None
    }
}

impl Read for VolumeReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() || self.position >= self.total {
            return Ok(0);
        }
        let Some((index, offset)) = self.locate(self.position) else {
            return Ok(0);
        };
        let available = self.lengths[index] - offset;
        let want = buf.len().min(available.min(buf.len() as u64) as usize);
        if want == 0 {
            return Ok(0);
        }
        self.files[index].seek(SeekFrom::Start(offset))?;
        let read = self.files[index].read(&mut buf[..want])?;
        self.position += read as u64;
        Ok(read)
    }
}

impl Seek for VolumeReader {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        let target = match position {
            SeekFrom::Start(offset) => i128::from(offset),
            SeekFrom::Current(delta) => i128::from(self.position) + i128::from(delta),
            SeekFrom::End(delta) => i128::from(self.total) + i128::from(delta),
        };
        if target < 0 || target > i128::from(u64::MAX) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "seek outside volume stream",
            ));
        }
        self.position = target as u64;
        Ok(self.position)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::OnceLock;

    fn scratch_dir() -> &'static Path {
        static SCRATCH: OnceLock<PathBuf> = OnceLock::new();
        SCRATCH.get_or_init(|| {
            let preferred = std::env::temp_dir();
            let probe = preferred.join(format!("acx-w1-005-probe-{}.tmp", std::process::id()));
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

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(tag: &str) -> Self {
            static NEXT_ID: AtomicU64 = AtomicU64::new(0);
            let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_nanos())
                .unwrap_or(0);
            let path = scratch_dir().join(format!(
                "acx-w1-005-{tag}-{}-{nanos}-{id}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).expect("create temp dir");
            Self { path }
        }

        fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
            let path = self.path.join(name);
            std::fs::write(&path, bytes).expect("write fixture");
            path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    const RAR5_MAGIC: &[u8] = b"Rar!\x1a\x07\x01\x00";
    const SEVENZ_MAGIC: &[u8] = b"7z\xbc\xaf\x27\x1c";

    #[test]
    fn numeric_split_reads_across_parts() {
        let temp = TempDir::new("numeric");
        temp.write("movie.7z.001", SEVENZ_MAGIC);
        temp.write("movie.7z.002", b"second");
        let source = ArchiveSource::resolve(&temp.path.join("movie.7z.001")).expect("resolve");
        assert_eq!(source.parts.len(), 2);
        let mut reader = source.reader().expect("reader");
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).expect("read all");
        assert_eq!(&bytes[..SEVENZ_MAGIC.len()], SEVENZ_MAGIC);
        assert_eq!(&bytes[SEVENZ_MAGIC.len()..], b"second");
    }

    #[test]
    fn four_digit_numeric_split_is_supported() {
        let temp = TempDir::new("numeric4");
        temp.write("movie.7z.0001", SEVENZ_MAGIC);
        temp.write("movie.7z.0002", b"rest");
        let source =
            ArchiveSource::resolve(&temp.path.join("movie.7z.0001")).expect("resolve 0001");
        assert_eq!(source.parts.len(), 2);
        assert!(source.parts[1].ends_with("movie.7z.0002"));
    }

    #[test]
    fn complete_numeric_extension_is_single() {
        let temp = TempDir::new("numeric-extension");
        let path = temp.write("movie.2024", b"PK\x03\x04");
        let source = ArchiveSource::resolve(&path).expect("resolve year extension");
        assert_eq!(source.parts.len(), 1);
        assert_eq!(source.format, ArchiveFormat::Zip);
    }

    #[test]
    fn complete_r01_extension_is_single() {
        let temp = TempDir::new("r01-extension");
        let path = temp.write("movie.r01", RAR5_MAGIC);
        let source = ArchiveSource::resolve(&path).expect("resolve r01 extension");
        assert_eq!(source.parts.len(), 1);
        assert_eq!(source.format, ArchiveFormat::Rar5);
    }

    #[test]
    fn final_part_can_be_reported_missing() {
        let temp = TempDir::new("final-gap");
        temp.write("movie.7z.001", SEVENZ_MAGIC);
        temp.write("movie.7z.002", b"second");
        let source =
            ArchiveSource::resolve(&temp.path.join("movie.7z.001")).expect("resolve parts");
        let next = source.missing_next_part().expect("next part");
        assert!(next.ends_with("movie.7z.003"), "{}", next.display());
    }

    #[test]
    fn numeric_gap_is_a_missing_volume() {
        let temp = TempDir::new("numeric-gap");
        temp.write("movie.7z.001", SEVENZ_MAGIC);
        temp.write("movie.7z.003", b"third");
        let error = ArchiveSource::resolve(&temp.path.join("movie.7z.001"))
            .expect_err("gap must be rejected");
        assert!(matches!(error, AcxError::MissingVolume(_)));
        assert!(error.to_string().contains("002"), "{error}");
    }

    #[test]
    fn later_numeric_part_resolves_back_to_first() {
        let temp = TempDir::new("numeric-later");
        temp.write("movie.zip.001", b"PK\x03\x04");
        temp.write("movie.zip.002", b"rest");
        let source = ArchiveSource::resolve(&temp.path.join("movie.zip.002")).expect("resolve");
        assert!(source.first_path().ends_with("movie.zip.001"));
    }

    #[test]
    fn missing_first_rar_part_names_part1() {
        let temp = TempDir::new("rar-missing-first");
        let path = temp.write("movie.part2.rar", RAR5_MAGIC);
        let error = ArchiveSource::resolve(&path).expect_err("part1 must be reported");
        assert!(matches!(error, AcxError::MissingVolume(_)));
        assert!(error.to_string().contains("part1.rar"), "{error}");
    }

    #[test]
    fn rar_part_gap_is_a_missing_volume() {
        let temp = TempDir::new("rar-part");
        temp.write("movie.part1.rar", RAR5_MAGIC);
        temp.write("movie.part3.rar", RAR5_MAGIC);
        let error = ArchiveSource::resolve(&temp.path.join("movie.part1.rar"))
            .expect_err("gap must be rejected");
        assert!(matches!(error, AcxError::MissingVolume(_)));
        assert!(error.to_string().contains("part2.rar"), "{error}");
    }

    #[test]
    fn old_rar_r00_volumes_are_ordered() {
        let temp = TempDir::new("rar-old");
        temp.write("movie.rar", RAR5_MAGIC);
        temp.write("movie.r00", b"zero");
        temp.write("movie.r01", b"one");
        let source = ArchiveSource::resolve(&temp.path.join("movie.rar")).expect("resolve");
        assert_eq!(source.parts.len(), 3);
        assert!(source.parts[0].ends_with("movie.rar"));
        assert!(source.parts[1].ends_with("movie.r00"));
        assert!(source.parts[2].ends_with("movie.r01"));
    }

    #[test]
    fn volume_reader_seeks_across_part_boundaries() {
        let temp = TempDir::new("reader-seek");
        temp.write("data.001", b"PK\x03\x04");
        temp.write("data.002", b"efgh");
        let source = ArchiveSource::resolve(&temp.path.join("data.001")).expect("resolve");
        let mut reader = source.reader().expect("reader");

        reader.seek(SeekFrom::Start(3)).expect("seek start");
        let mut buf = [0u8; 4];
        reader.read_exact(&mut buf).expect("read across");
        assert_eq!(&buf, b"\x04efg");

        reader.seek(SeekFrom::End(-2)).expect("seek end");
        let mut tail = [0u8; 2];
        reader.read_exact(&mut tail).expect("read tail");
        assert_eq!(&tail, b"gh");
    }

    #[test]
    fn sfx_stub_is_skipped() {
        let temp = TempDir::new("sfx");
        let mut payload = b"MZ".to_vec();
        payload.extend(std::iter::repeat_n(b'x', 100));
        payload.extend_from_slice(SEVENZ_MAGIC);
        payload.extend_from_slice(b"payload");
        let path = temp.write("archive.exe", &payload);
        let source = ArchiveSource::resolve(&path).expect("resolve SFX");
        assert_eq!(source.format, ArchiveFormat::SevenZ);
        assert_eq!(source.start_offset, 102);
        let mut reader = source.reader().expect("reader");
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes).expect("read");
        assert_eq!(&bytes[..SEVENZ_MAGIC.len()], SEVENZ_MAGIC);
    }

    #[test]
    fn rar_sfx_stub_is_detected() {
        let temp = TempDir::new("sfx-rar");
        let mut payload = b"MZ".to_vec();
        payload.extend(std::iter::repeat_n(b'x', 64));
        payload.extend_from_slice(RAR5_MAGIC);
        let path = temp.write("archive.exe", &payload);
        let source = ArchiveSource::resolve(&path).expect("resolve RAR SFX");
        assert_eq!(source.format, ArchiveFormat::Rar5);
        assert_eq!(source.start_offset, 66);
    }

    #[test]
    fn pe_without_payload_is_unsupported() {
        let temp = TempDir::new("sfx-empty");
        let path = temp.write("installer.exe", b"MZ-not-an-archive");
        let error = ArchiveSource::resolve(&path).expect_err("must reject stub-only PE");
        assert!(matches!(error, AcxError::Unsupported(_)));
    }

    #[test]
    fn pkzip_z01_is_unsupported() {
        let temp = TempDir::new("z01");
        let path = temp.write("archive.z01", b"PK\x03\x04");
        let error = ArchiveSource::resolve(&path).expect_err("z01 must be rejected");
        assert!(matches!(error, AcxError::Unsupported(_)));
        assert!(error.to_string().contains("spanned"));
    }

    #[test]
    fn pkzip_z01_descriptor_magic_is_unsupported() {
        let temp = TempDir::new("z01-descriptor");
        let path = temp.write("archive.z01", b"PK\x07\x08");
        let error = ArchiveSource::resolve(&path).expect_err("z01 must be rejected");
        assert!(matches!(error, AcxError::Unsupported(_)));
        assert!(error.to_string().contains("spanned"));
    }
}
