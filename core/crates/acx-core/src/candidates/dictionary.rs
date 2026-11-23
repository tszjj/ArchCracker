// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

//! Dictionary candidate source.
//!
//! W1 reads the whole dictionary into memory; streaming is a W2 concern.
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

use crate::error::{AcxError, Result};
use std::collections::HashSet;
use std::path::Path;

const UTF8_BOM: &[u8] = &[0xEF, 0xBB, 0xBF];
const UTF16_LE_BOM: &[u8] = &[0xFF, 0xFE];
const UTF16_BE_BOM: &[u8] = &[0xFE, 0xFF];

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
}
