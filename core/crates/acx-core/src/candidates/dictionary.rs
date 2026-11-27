// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

//! Dictionary candidate source.
//!
//! W1 reads small dictionaries into memory; [`DictionaryStream`] is the
//! bounded-memory path used by the CLI. Streaming preserves file order and does
//! not perform global de-duplication: duplicate lines may be retried, which is
//! safe for password search and keeps the candidate index a stable checkpoint
//! watermark.
//!
//! Encoding order:
//! 1. UTF-8 BOM, UTF-16LE BOM, or UTF-16BE BOM (authoritative when present);
//! 2. otherwise strict UTF-8;
//! 3. otherwise GBK/GB18030 via [`encoding_rs::GBK`], whose decoder is the
//!    gb18030 decoder. That last step is lossy: undecodable byte sequences
//!    become U+FFFD instead of failing the load.
//!
//! Every accepted line is kept verbatim as UTF-8 bytes: empty lines are
//! skipped, but leading and trailing spaces are preserved because they may be
//! part of a password.

use super::{CandidateBatch, CandidateSource, MAX_BATCH_BYTES};
use crate::error::{AcxError, Result};
use encoding_rs::{Decoder, Encoding, GBK, UTF_16BE, UTF_16LE, UTF_8};
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::Path;

const UTF8_BOM: &[u8] = &[0xEF, 0xBB, 0xBF];
const UTF16_LE_BOM: &[u8] = &[0xFF, 0xFE];
const UTF16_BE_BOM: &[u8] = &[0xFE, 0xFF];
const STREAM_CHUNK_BYTES: usize = 64 * 1024;
const MAX_LINE_BYTES: usize = 1024 * 1024;

pub struct Dictionary {
    entries: Vec<Vec<u8>>,
}

impl Dictionary {
    /// Load a dictionary file from `path`.
    ///
    /// Returns [`AcxError::Io`] when the file cannot be read and
    /// [`AcxError::Dictionary`] when an explicitly declared encoding (UTF-8
    /// BOM or UTF-16 BOM) cannot be decoded.
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read(path)?;
        let text = decode(&raw)?;

        let mut entries = Vec::new();
        let mut seen: HashSet<Vec<u8>> = HashSet::new();
        for line in text.split(['\n', '\r']) {
            if line.is_empty() {
                continue;
            }
            let password = line.as_bytes().to_vec();
            if seen.contains(password.as_slice()) {
                continue;
            }
            seen.insert(password.clone());
            entries.push(password);
        }

        Ok(Self { entries })
    }

    /// Passwords in first-occurrence order, as UTF-8 bytes.
    pub fn entries(&self) -> &[Vec<u8>] {
        &self.entries
    }

    /// Number of unique, non-empty passwords.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the dictionary has no passwords.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Consume the loader without making a second copy of every candidate.
    pub fn into_entries(self) -> Vec<Vec<u8>> {
        self.entries
    }
}

/// Bounded-memory dictionary source used by the CLI.
///
/// Opening scans the file once to learn the exact candidate count, then reopens
/// it and skips `skip` lines. During an attack only one decoded chunk and one
/// scheduler batch are resident. Resume therefore costs a sequential skip, not
/// a multi-gigabyte heap.
pub struct DictionaryStream {
    reader: LineReader,
    total: usize,
    max_line_bytes: usize,
    next_index: usize,
    held_line: Option<String>,
}

impl DictionaryStream {
    pub fn open(path: &Path, skip: usize) -> Result<Self> {
        let scan = scan_dictionary(path)?;
        if skip > scan.lines {
            return Err(AcxError::Dictionary(format!(
                "checkpoint candidate {skip} exceeds dictionary length {}",
                scan.lines
            )));
        }

        let mut reader = LineReader::open(path, scan.force)?;
        for _ in 0..skip {
            if reader.next_line()?.is_none() {
                return Err(AcxError::Dictionary(format!(
                    "dictionary ended while skipping to candidate {skip}"
                )));
            }
        }
        Ok(Self {
            reader,
            total: scan.lines,
            max_line_bytes: scan.max_line_bytes,
            next_index: skip,
            held_line: None,
        })
    }

    pub fn total(&self) -> usize {
        self.total
    }

    /// Longest decoded line, for the job/batch memory estimate.
    pub fn max_line_bytes(&self) -> usize {
        self.max_line_bytes
    }
}

impl CandidateSource for DictionaryStream {
    fn total(&self) -> usize {
        self.total
    }

    fn next_batch(&mut self, max: usize) -> Result<Option<CandidateBatch>> {
        if max == 0 {
            return Ok(None);
        }
        let start_index = self.next_index;
        let mut candidates = Vec::with_capacity(max);
        let mut bytes = 0usize;
        if let Some(line) = self.held_line.take() {
            bytes += line.len();
            candidates.push(line.into_bytes());
            self.next_index += 1;
        }
        while candidates.len() < max {
            if bytes >= MAX_BATCH_BYTES {
                break;
            }
            let Some(line) = self.reader.next_line()? else {
                break;
            };
            let line_len = line.len();
            if !candidates.is_empty() && bytes.saturating_add(line_len) > MAX_BATCH_BYTES {
                self.held_line = Some(line);
                break;
            }
            self.next_index += 1;
            bytes += line_len;
            candidates.push(line.into_bytes());
        }
        if candidates.is_empty() {
            if self.next_index != self.total {
                return Err(AcxError::Dictionary(format!(
                    "dictionary ended at candidate {} before the scanned total {}",
                    self.next_index, self.total
                )));
            }
            Ok(None)
        } else {
            Ok(Some(CandidateBatch {
                start_index,
                candidates,
            }))
        }
    }
}

/// Result of one line-counting scan. `force` records the decoder that succeeded
/// so callers can reopen the file without another full scan and without
/// re-guessing the encoding.
#[derive(Debug, Clone, Copy)]
pub(crate) struct DictionaryScan {
    pub lines: usize,
    pub max_line_bytes: usize,
    pub force: Option<&'static Encoding>,
}

/// Count non-empty lines and record the longest decoded line.
///
/// BOM-less files can look like ASCII at the start and contain legacy
/// GBK/GB18030 bytes later; retry with the lossy GBK decoder in that case.
pub(crate) fn scan_dictionary(path: &Path) -> Result<DictionaryScan> {
    match scan_dictionary_inner(path, None) {
        Ok(scan) => Ok(scan),
        Err(error) if is_invalid_utf8(&error) => scan_dictionary_inner(path, Some(GBK)),
        Err(error) => Err(error),
    }
}

fn scan_dictionary_inner(path: &Path, force: Option<&'static Encoding>) -> Result<DictionaryScan> {
    let mut reader = LineReader::open(path, force)?;
    let mut lines = 0usize;
    let mut max_line_bytes = 0usize;
    while let Some(line) = reader.next_line()? {
        lines += 1;
        max_line_bytes = max_line_bytes.max(line.len());
    }
    Ok(DictionaryScan {
        lines,
        max_line_bytes,
        force,
    })
}

fn is_invalid_utf8(error: &AcxError) -> bool {
    matches!(error, AcxError::Dictionary(message) if message.starts_with("invalid UTF-8"))
}

/// A chunked decoder that yields newline/CR-delimited UTF-8 lines.
pub(crate) struct LineReader {
    input: BufReader<File>,
    decoder: Decoder,
    pending: String,
    cursor: usize,
    eof: bool,
    strict: bool,
    label: &'static str,
}

impl LineReader {
    pub(crate) fn open(path: &Path, force: Option<&'static Encoding>) -> Result<Self> {
        let mut file = File::open(path)?;
        // Read up to three bytes for BOM detection, then rewind. A single
        // `BufReader::fill_buf` is not guaranteed to return three bytes.
        let mut prefix = [0u8; 3];
        let mut prefix_len = 0;
        while prefix_len < prefix.len() {
            let read = file.read(&mut prefix[prefix_len..])?;
            if read == 0 {
                break;
            }
            prefix_len += read;
        }
        file.seek(SeekFrom::Start(0))?;
        let mut input = BufReader::with_capacity(STREAM_CHUNK_BYTES, file);
        let sample = &prefix[..prefix_len];
        let (encoding, bom_len, strict, label) = if sample.starts_with(UTF8_BOM) {
            (UTF_8, UTF8_BOM.len(), true, "UTF-8")
        } else if sample.starts_with(UTF16_LE_BOM) {
            (UTF_16LE, UTF16_LE_BOM.len(), true, "UTF-16LE")
        } else if sample.starts_with(UTF16_BE_BOM) {
            (UTF_16BE, UTF16_BE_BOM.len(), true, "UTF-16BE")
        } else if let Some(encoding) = force {
            (encoding, 0, false, "GBK/GB18030")
        } else if utf8_sample_is_valid_or_incomplete(sample) {
            (UTF_8, 0, true, "UTF-8")
        } else {
            // Mirrors Dictionary::load: invalid BOM-less UTF-8 falls back
            // to the lossy GBK/GB18030 decoder.
            (GBK, 0, false, "GBK/GB18030")
        };
        input.seek(SeekFrom::Start(bom_len as u64))?;
        Ok(Self {
            input,
            decoder: encoding.new_decoder_without_bom_handling(),
            pending: String::new(),
            cursor: 0,
            eof: false,
            strict,
            label,
        })
    }

    pub(crate) fn next_line(&mut self) -> Result<Option<String>> {
        loop {
            if let Some(relative) = self.pending[self.cursor..].find(['\n', '\r']) {
                let end = self.cursor + relative;
                let line = self.pending[self.cursor..end].to_string();
                self.cursor = end + 1;
                if !line.is_empty() {
                    return Ok(Some(line));
                }
                continue;
            }
            if self.eof {
                if self.cursor >= self.pending.len() {
                    return Ok(None);
                }
                let line = self.pending[self.cursor..].to_string();
                self.cursor = self.pending.len();
                return Ok(Some(line));
            }
            // Retain only the incomplete tail before appending the next chunk;
            // splitting a fresh chunk removes the previous O(n) copy per line.
            if self.cursor > 0 {
                self.pending.drain(..self.cursor);
                self.cursor = 0;
            }
            self.fill()?;
        }
    }

    fn fill(&mut self) -> Result<()> {
        let mut bytes = [0u8; STREAM_CHUNK_BYTES];
        let read = self.input.read(&mut bytes)?;
        let last = read == 0;
        // `decode_to_string` writes into the string's spare capacity, so it
        // needs room before the first call; give it a worst-case UTF-8 budget.
        let mut decoded = String::with_capacity(read.saturating_mul(4).max(1024));
        let mut offset = 0;
        loop {
            let (_, consumed, had_errors) =
                self.decoder
                    .decode_to_string(&bytes[offset..read], &mut decoded, last);
            if had_errors && self.strict {
                return Err(AcxError::Dictionary(format!(
                    "invalid {} sequence in dictionary",
                    self.label
                )));
            }
            offset += consumed;
            if last || offset >= read {
                break;
            }
            if consumed == 0 {
                // OutputFull: grow and retry the same input.
                decoded.reserve(STREAM_CHUNK_BYTES);
            }
        }
        self.pending.push_str(&decoded);
        let tail = &self.pending[self.cursor..];
        let current_line_len = tail.find(['\n', '\r']).unwrap_or(tail.len());
        if current_line_len > MAX_LINE_BYTES {
            return Err(AcxError::Dictionary(format!(
                "dictionary line exceeds the {MAX_LINE_BYTES}-byte streaming limit"
            )));
        }
        if last {
            self.eof = true;
        }
        Ok(())
    }
}

fn utf8_sample_is_valid_or_incomplete(sample: &[u8]) -> bool {
    match std::str::from_utf8(sample) {
        Ok(_) => true,
        // A chunk boundary can split a multi-byte character. Treat only an
        // incomplete final character as UTF-8; a real error means GBK.
        Err(error) => error.error_len().is_none(),
    }
}

/// Decode the raw dictionary bytes into text.
fn decode(raw: &[u8]) -> Result<String> {
    if let Some(rest) = raw.strip_prefix(UTF8_BOM) {
        return std::str::from_utf8(rest)
            .map(str::to_owned)
            .map_err(|error| AcxError::Dictionary(format!("invalid UTF-8 after BOM: {error}")));
    }
    if let Some(rest) = raw.strip_prefix(UTF16_LE_BOM) {
        return decode_utf16(rest, true, "UTF-16LE");
    }
    if let Some(rest) = raw.strip_prefix(UTF16_BE_BOM) {
        return decode_utf16(rest, false, "UTF-16BE");
    }

    match std::str::from_utf8(raw) {
        Ok(text) => Ok(text.to_owned()),
        Err(_) => {
            // `encoding_rs::GBK`'s decoder is the gb18030 decoder, so it also
            // accepts four-byte GB18030 sequences. It never fails; malformed
            // input is replaced with U+FFFD. BOM sniffing is already handled
            // above, so decode without it.
            let (decoded, _) = encoding_rs::GBK.decode_without_bom_handling(raw);
            Ok(decoded.into_owned())
        }
    }
}

/// Decode UTF-16 code units after the BOM has been stripped.
fn decode_utf16(bytes: &[u8], little_endian: bool, label: &str) -> Result<String> {
    let (pairs, remainder) = bytes.as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(AcxError::Dictionary(format!(
            "{label} input has an odd byte length ({})",
            bytes.len()
        )));
    }

    let units: Vec<u16> = pairs
        .iter()
        .map(|pair| {
            if little_endian {
                u16::from_le_bytes(*pair)
            } else {
                u16::from_be_bytes(*pair)
            }
        })
        .collect();

    String::from_utf16(&units)
        .map_err(|error| AcxError::Dictionary(format!("invalid {label} input: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::OnceLock;

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    /// Directory for test dictionaries, preferring the OS temp directory.
    ///
    /// Some confined harnesses deny child processes writes under `%TEMP%`
    /// while allowing writes under the build's `target/` tree; probe and fall
    /// back so the unit tests do not fail for an environment reason.
    fn scratch_dir() -> &'static Path {
        static SCRATCH: OnceLock<PathBuf> = OnceLock::new();
        SCRATCH.get_or_init(|| {
            let preferred = std::env::temp_dir();
            let probe = preferred.join(format!(
                "acx-core-dictionary-probe-{}.tmp",
                std::process::id()
            ));
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

    /// Unique path under a writable scratch directory; no file is created.
    fn temp_path(name: &str) -> PathBuf {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        scratch_dir().join(format!(
            "acx-core-dictionary-{}-{id}-{name}",
            std::process::id()
        ))
    }

    /// Temporary dictionary file removed on drop, including on test panic.
    struct TempFile {
        path: PathBuf,
    }

    impl TempFile {
        fn new(name: &str, contents: &[u8]) -> Self {
            let path = temp_path(name);
            std::fs::write(&path, contents)
                .unwrap_or_else(|error| panic!("write {}: {error}", path.display()));
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    #[test]
    fn loads_utf8_in_order_and_dedupes_without_trimming() {
        let file = TempFile::new(
            "utf8.txt",
            "alpha\r\nbeta\n\nalpha\n  spaced  \n   \nbeta\ngamma\r".as_bytes(),
        );

        let dictionary = Dictionary::load(file.path()).expect("load UTF-8 dictionary");

        let expected: &[Vec<u8>] = &[
            b"alpha".to_vec(),
            b"beta".to_vec(),
            b"  spaced  ".to_vec(),
            b"   ".to_vec(),
            b"gamma".to_vec(),
        ];
        assert_eq!(dictionary.entries(), expected);
        assert_eq!(dictionary.len(), 5);
        assert!(!dictionary.is_empty());
    }

    #[test]
    fn strips_utf8_bom() {
        let mut raw = UTF8_BOM.to_vec();
        raw.extend("first\nsecond".as_bytes());

        let file = TempFile::new("utf8bom.txt", &raw);
        let dictionary = Dictionary::load(file.path()).expect("load UTF-8 BOM dictionary");

        let expected: &[Vec<u8>] = &[b"first".to_vec(), b"second".to_vec()];
        assert_eq!(dictionary.entries(), expected);
    }

    #[test]
    fn loads_gbk_dictionary_via_fallback() {
        let (encoded, _, had_errors) = encoding_rs::GBK.encode("中文密码\nP@ss");
        assert!(!had_errors, "GBK must encode the test input");

        let file = TempFile::new("gbk.txt", &encoded);
        let dictionary = Dictionary::load(file.path()).expect("load GBK dictionary");

        assert_eq!(dictionary.len(), 2);
        assert_eq!(dictionary.entries()[0], "中文密码".as_bytes());
        assert_eq!(dictionary.entries()[1], b"P@ss".as_slice());
    }

    #[test]
    fn loads_utf16le_with_bom() {
        let mut raw = UTF16_LE_BOM.to_vec();
        raw.extend(
            "pässwörd\r\n第二个\n"
                .encode_utf16()
                .flat_map(u16::to_le_bytes),
        );

        let file = TempFile::new("utf16le.txt", &raw);
        let dictionary = Dictionary::load(file.path()).expect("load UTF-16LE dictionary");

        let expected: &[Vec<u8>] = &["pässwörd".as_bytes().to_vec(), "第二个".as_bytes().to_vec()];
        assert_eq!(dictionary.entries(), expected);
    }

    #[test]
    fn loads_utf16be_with_bom() {
        let mut raw = UTF16_BE_BOM.to_vec();
        raw.extend(
            "pässwörd\nzweite\n"
                .encode_utf16()
                .flat_map(u16::to_be_bytes),
        );

        let file = TempFile::new("utf16be.txt", &raw);
        let dictionary = Dictionary::load(file.path()).expect("load UTF-16BE dictionary");

        let expected: &[Vec<u8>] = &["pässwörd".as_bytes().to_vec(), b"zweite".to_vec()];
        assert_eq!(dictionary.entries(), expected);
    }

    #[test]
    fn rejects_malformed_utf16() {
        let raw = [0xFF, 0xFE, b'a'];
        let file = TempFile::new("utf16-odd.txt", &raw);

        let error = match Dictionary::load(file.path()) {
            Ok(_) => panic!("odd-length UTF-16 input must fail"),
            Err(error) => error,
        };
        assert!(matches!(error, AcxError::Dictionary(_)));
    }

    #[test]
    fn missing_file_is_io_error() {
        let path = temp_path("missing.txt");
        let _ = std::fs::remove_file(&path);

        let error = match Dictionary::load(&path) {
            Ok(_) => panic!("loading a missing dictionary must fail"),
            Err(error) => error,
        };
        assert!(matches!(error, AcxError::Io(_)));
    }

    #[test]
    fn stream_preserves_order_and_batches() {
        let file = TempFile::new("stream.txt", "alpha\r\nbeta\n\n  spaced  \nlast".as_bytes());
        let mut stream = DictionaryStream::open(file.path(), 0).expect("open stream");
        assert_eq!(stream.total(), 4);

        let first = stream
            .next_batch(2)
            .expect("first batch")
            .expect("not empty");
        assert_eq!(first.start_index, 0);
        assert_eq!(first.candidates, vec![b"alpha".to_vec(), b"beta".to_vec()]);

        let second = stream
            .next_batch(2)
            .expect("second batch")
            .expect("not empty");
        assert_eq!(second.start_index, 2);
        assert_eq!(
            second.candidates,
            vec![b"  spaced  ".to_vec(), b"last".to_vec()]
        );
        assert!(stream.next_batch(2).expect("eof").is_none());
    }

    #[test]
    fn stream_skip_starts_at_the_checkpoint_index() {
        let file = TempFile::new("stream-skip.txt", "one\ntwo\nthree\n".as_bytes());
        let mut stream = DictionaryStream::open(file.path(), 1).expect("open stream");
        let batch = stream.next_batch(10).expect("batch").expect("not empty");
        assert_eq!(stream.total(), 3);
        assert_eq!(batch.start_index, 1);
        assert_eq!(batch.candidates, vec![b"two".to_vec(), b"three".to_vec()]);
    }

    #[test]
    fn stream_keeps_duplicate_lines() {
        let file = TempFile::new("stream-dupes.txt", "same\nsame\n".as_bytes());
        let mut stream = DictionaryStream::open(file.path(), 0).expect("open stream");
        let batch = stream.next_batch(10).expect("batch").expect("not empty");
        assert_eq!(stream.total(), 2);
        assert_eq!(batch.candidates, vec![b"same".to_vec(), b"same".to_vec()]);
    }

    #[test]
    fn stream_decodes_gbk() {
        let (encoded, _, had_errors) = encoding_rs::GBK.encode("中文密码\nP@ss");
        assert!(!had_errors);
        let file = TempFile::new("stream-gbk.txt", &encoded);
        let mut stream = DictionaryStream::open(file.path(), 0).expect("open stream");
        let batch = stream.next_batch(10).expect("batch").expect("not empty");
        assert_eq!(
            batch.candidates,
            vec!["中文密码".as_bytes().to_vec(), b"P@ss".to_vec()]
        );
    }

    #[test]
    fn stream_strips_utf8_bom() {
        let mut raw = UTF8_BOM.to_vec();
        raw.extend_from_slice(b"first\nsecond\n");
        let file = TempFile::new("stream-utf8bom.txt", &raw);
        let mut stream = DictionaryStream::open(file.path(), 0).expect("open stream");
        let batch = stream.next_batch(10).expect("batch").expect("not empty");
        assert_eq!(
            batch.candidates,
            vec![b"first".to_vec(), b"second".to_vec()]
        );
    }

    #[test]
    fn stream_decodes_utf16le_with_bom() {
        let mut raw = UTF16_LE_BOM.to_vec();
        raw.extend(
            "pässwörd\r\n第二个\n"
                .encode_utf16()
                .flat_map(u16::to_le_bytes),
        );
        let file = TempFile::new("stream-utf16le.txt", &raw);
        let mut stream = DictionaryStream::open(file.path(), 0).expect("open stream");
        let batch = stream.next_batch(10).expect("batch").expect("not empty");
        assert_eq!(
            batch.candidates,
            vec!["pässwörd".as_bytes().to_vec(), "第二个".as_bytes().to_vec()]
        );
    }

    #[test]
    fn stream_decodes_utf16be_with_bom() {
        let mut raw = UTF16_BE_BOM.to_vec();
        raw.extend(
            "pässwörd\nzweite\n"
                .encode_utf16()
                .flat_map(u16::to_be_bytes),
        );
        let file = TempFile::new("stream-utf16be.txt", &raw);
        let mut stream = DictionaryStream::open(file.path(), 0).expect("open stream");
        let batch = stream.next_batch(10).expect("batch").expect("not empty");
        assert_eq!(
            batch.candidates,
            vec!["pässwörd".as_bytes().to_vec(), b"zweite".to_vec()]
        );
    }

    #[test]
    fn stream_falls_back_to_gbk_after_a_valid_utf8_sample() {
        // The first 64 KiB looks like ASCII; the invalid byte appears only
        // later. This mirrors the real rockyou.txt case.
        let mut raw = Vec::new();
        for _ in 0..70_000 {
            raw.extend_from_slice(b"ascii-password\n");
        }
        raw.extend_from_slice(&[0xFF, b'\n']);

        let file = TempFile::new("stream-late-gbk.txt", &raw);
        let mut stream = DictionaryStream::open(file.path(), 0).expect("fallback stream");
        assert_eq!(stream.total(), 70_001);
        let batch = stream.next_batch(10).expect("batch").expect("not empty");
        assert_eq!(batch.candidates[0], b"ascii-password");
    }

    #[test]
    fn stream_rejects_an_overlong_line() {
        let file = TempFile::new("stream-long-line.txt", &vec![b'a'; MAX_LINE_BYTES + 1]);
        let error = match DictionaryStream::open(file.path(), 0) {
            Ok(_) => panic!("overlong line must fail"),
            Err(error) => error,
        };
        assert!(matches!(error, AcxError::Dictionary(_)));
    }
}
