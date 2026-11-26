// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

//! W2-003 brute-force candidate source.
//!
//! A brute spec is one ordered byte charset plus an inclusive length range.
//! Candidates are produced shortest-first; within one length the rightmost
//! position advances fastest (odometer order), so the global candidate index is
//! a stable checkpoint watermark. The keyspace is estimated in `u128` but the
//! execution index stays `usize`, matching [`CandidateSource`].

use crate::candidates::mask::{
    expand_charset_with, hex_sha256, parse_custom_sets, LARGE_KEYSPACE_WARNING, MAX_MASK_POSITIONS,
    RECOMMENDED_MASK_POSITIONS,
};
use crate::candidates::{CandidateBatch, CandidateSource};
use crate::error::{AcxError, Result};
use crate::estimate::{estimate_space, SpaceEstimate, SpaceInput};

/// Hard upper bound for `--max-len`; matches the W2-002 mask position limit.
pub const MAX_BRUTE_LENGTH: usize = MAX_MASK_POSITIONS;
/// Lengths above this value produce a warning; matches W2-002.
pub const RECOMMENDED_BRUTE_LENGTH: usize = RECOMMENDED_MASK_POSITIONS;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BruteSpec {
    charset_text: String,
    charset: Vec<u8>,
    min_len: usize,
    max_len: usize,
    per_len: Vec<u128>,
    keyspace: u128,
}

impl BruteSpec {
    /// Parse a brute spec. `custom` contains the already-expanded `?1..?4`
    /// sets; `None` means that set is undefined.
    pub fn parse(
        charset_text: &str,
        custom: &[Option<Vec<u8>>; 4],
        min_len: usize,
        max_len: usize,
    ) -> Result<Self> {
        if min_len == 0 {
            return Err(AcxError::Attack("--min-len must be at least 1".to_string()));
        }
        if min_len > max_len {
            return Err(AcxError::Attack(format!(
                "--min-len {min_len} exceeds --max-len {max_len}"
            )));
        }
        if max_len > MAX_BRUTE_LENGTH {
            return Err(AcxError::Attack(format!(
                "--max-len {max_len} exceeds the maximum of {MAX_BRUTE_LENGTH}"
            )));
        }
        let charset = expand_charset_with(charset_text, custom)?;

        let radix = charset.len() as u128;
        let mut per_len = Vec::with_capacity(max_len - min_len + 1);
        let mut keyspace = 0u128;
        let mut power = 1u128;
        for length in 1..=max_len {
            power = power.checked_mul(radix).ok_or_else(|| {
                AcxError::Attack(
                    "brute keyspace exceeds u128; reduce the charset or --max-len".to_string(),
                )
            })?;
            if length >= min_len {
                keyspace = keyspace.checked_add(power).ok_or_else(|| {
                    AcxError::Attack(
                        "brute keyspace exceeds u128; reduce the charset or --max-len".to_string(),
                    )
                })?;
                per_len.push(power);
            }
        }

        Ok(Self {
            charset_text: charset_text.to_string(),
            charset,
            min_len,
            max_len,
            per_len,
            keyspace,
        })
    }

    pub fn source_text(&self) -> &str {
        &self.charset_text
    }

    pub fn charset(&self) -> &[u8] {
        &self.charset
    }

    pub fn min_len(&self) -> usize {
        self.min_len
    }

    pub fn max_len(&self) -> usize {
        self.max_len
    }

    /// Keyspace per length, starting at `min_len`.
    pub fn per_len(&self) -> &[u128] {
        &self.per_len
    }

    pub fn keyspace(&self) -> u128 {
        self.keyspace
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BruteWarning {
    LongLength { max_len: usize, recommended: usize },
    LargeKeyspace { keyspace: u128, threshold: u128 },
    TooLargeToRun { keyspace: u128, max: u128 },
}

impl std::fmt::Display for BruteWarning {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LongLength {
                max_len,
                recommended,
            } => write!(
                formatter,
                "brute max length {max_len} exceeds the recommended maximum {recommended}"
            ),
            Self::LargeKeyspace {
                keyspace,
                threshold,
            } => write!(
                formatter,
                "brute keyspace {keyspace} exceeds warning threshold {threshold}"
            ),
            Self::TooLargeToRun {
                keyspace,
                max,
            } => write!(
                formatter,
                "brute keyspace {keyspace} exceeds executable limit {max}; only estimation is possible"
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BruteEstimate {
    pub keyspace: u128,
    pub fits_usize: bool,
    /// Keyspace per length, starting at `min_len`.
    pub per_len: Vec<u128>,
    pub warnings: Vec<BruteWarning>,
    /// Core-side memory estimate for `--estimate` and the pre-attack summary.
    pub space: SpaceEstimate,
}

#[derive(Debug, Clone)]
pub struct BruteSet {
    spec: BruteSpec,
    signature: String,
}

impl BruteSet {
    /// Parse the CLI view of a brute attack: the raw charset expression, the
    /// four raw custom-charset definitions, and the inclusive length range.
    pub fn parse(
        charset_text: &str,
        custom_texts: &[Option<String>; 4],
        min_len: usize,
        max_len: usize,
    ) -> Result<Self> {
        let custom_sets = parse_custom_sets(custom_texts)?;
        let spec = BruteSpec::parse(charset_text, &custom_sets, min_len, max_len)?;
        let signature = brute_signature(charset_text, custom_texts, min_len, max_len);
        Ok(Self { spec, signature })
    }

    pub fn spec(&self) -> &BruteSpec {
        &self.spec
    }

    pub fn charset(&self) -> &[u8] {
        self.spec.charset()
    }

    pub fn keyspace(&self) -> u128 {
        self.spec.keyspace()
    }

    pub fn signature(&self) -> &str {
        &self.signature
    }

    pub fn estimate(&self, threads: usize) -> BruteEstimate {
        let keyspace = self.spec.keyspace;
        let fits_usize = keyspace <= usize::MAX as u128;
        let mut warnings = Vec::new();
        if self.spec.max_len > RECOMMENDED_BRUTE_LENGTH {
            warnings.push(BruteWarning::LongLength {
                max_len: self.spec.max_len,
                recommended: RECOMMENDED_BRUTE_LENGTH,
            });
        }
        if keyspace > LARGE_KEYSPACE_WARNING {
            warnings.push(BruteWarning::LargeKeyspace {
                keyspace,
                threshold: LARGE_KEYSPACE_WARNING,
            });
        }
        if !fits_usize {
            warnings.push(BruteWarning::TooLargeToRun {
                keyspace,
                max: usize::MAX as u128,
            });
        }
        let space = estimate_space(&SpaceInput {
            total: keyspace,
            threads,
            max_candidate_bytes: self.spec.max_len as u128,
            batch_bytes_cap: None,
            source_bytes: 4096,
        });
        BruteEstimate {
            keyspace,
            fits_usize,
            per_len: self.spec.per_len.clone(),
            warnings,
            space,
        }
    }

    /// Turn the set into a scheduler source starting at a global candidate
    /// index. The source rejects keyspaces that do not fit the W1 `usize`
    /// index contract.
    pub fn into_source(self, start_index: usize) -> Result<BruteSource> {
        BruteSource::new(self.spec, start_index)
    }
}

fn brute_signature(
    charset_text: &str,
    custom: &[Option<String>; 4],
    min_len: usize,
    max_len: usize,
) -> String {
    let mut material = String::from("brute\n");
    for (index, text) in custom.iter().enumerate() {
        material.push_str(&format!(
            "custom{index}={}\n",
            text.as_deref().unwrap_or("")
        ));
    }
    material.push_str(&format!("charset={charset_text}\n"));
    material.push_str(&format!("min_len={min_len}\n"));
    material.push_str(&format!("max_len={max_len}\n"));
    hex_sha256(material.as_bytes())
}

pub struct BruteSource {
    charset: Vec<u8>,
    min_len: usize,
    length_count: usize,
    /// Index into the length range; `length_count` means the source is done.
    current: usize,
    digits: Vec<usize>,
    next_index: usize,
    total: usize,
}

impl BruteSource {
    fn new(spec: BruteSpec, start_index: usize) -> Result<Self> {
        let total = usize::try_from(spec.keyspace).map_err(|_| {
            AcxError::Attack(format!(
                "brute keyspace {} exceeds executable limit {}",
                spec.keyspace,
                usize::MAX
            ))
        })?;
        if start_index > total {
            return Err(AcxError::Attack(format!(
                "brute resume index {start_index} exceeds total {total}"
            )));
        }

        // `total` fits `usize`, so every per-length count and prefix does too.
        let mut prefixes = Vec::with_capacity(spec.per_len.len());
        let mut sum = 0usize;
        for count in &spec.per_len {
            prefixes.push(sum);
            sum += usize::try_from(*count).expect("per-length keyspace fits usize");
        }

        let (current, digits) = if start_index == total {
            (spec.per_len.len(), Vec::new())
        } else {
            let index = prefixes
                .partition_point(|prefix| *prefix <= start_index)
                .checked_sub(1)
                .expect("start_index is inside the keyspace");
            let local = start_index - prefixes[index];
            let length = spec.min_len + index;
            (index, decode_digits(local, length, spec.charset.len()))
        };

        Ok(Self {
            charset: spec.charset,
            min_len: spec.min_len,
            length_count: spec.per_len.len(),
            current,
            digits,
            next_index: start_index,
            total,
        })
    }

    fn candidate(&self) -> Vec<u8> {
        self.digits
            .iter()
            .map(|digit| self.charset[*digit])
            .collect()
    }

    fn advance(&mut self) -> bool {
        for digit in self.digits.iter_mut().rev() {
            *digit += 1;
            if *digit < self.charset.len() {
                return true;
            }
            *digit = 0;
        }
        false
    }
}

fn decode_digits(value: usize, length: usize, radix: usize) -> Vec<usize> {
    let mut digits = vec![0usize; length];
    let mut value = value;
    for digit in digits.iter_mut().rev() {
        *digit = value % radix;
        value /= radix;
    }
    debug_assert_eq!(value, 0, "resume index must fit the requested length");
    digits
}

impl CandidateSource for BruteSource {
    fn total(&self) -> usize {
        self.total
    }

    fn next_batch(&mut self, max: usize) -> Result<Option<CandidateBatch>> {
        if max == 0 || self.next_index >= self.total {
            return Ok(None);
        }
        let start_index = self.next_index;
        let mut candidates = Vec::with_capacity(max.min(self.total - self.next_index));
        while candidates.len() < max && self.current < self.length_count {
            candidates.push(self.candidate());
            self.next_index += 1;
            if !self.advance() {
                self.current += 1;
                if self.current < self.length_count {
                    // Grow the odometer for the next length, shortest first.
                    self.digits = vec![0usize; self.min_len + self.current];
                }
            }
        }
        if candidates.is_empty() {
            return Ok(None);
        }
        Ok(Some(CandidateBatch {
            start_index,
            candidates,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn custom(texts: [Option<&str>; 4]) -> [Option<String>; 4] {
        texts.map(|text| text.filter(|text| !text.is_empty()).map(str::to_string))
    }

    fn set(text: &str, min_len: usize, max_len: usize) -> BruteSet {
        BruteSet::parse(text, &[None, None, None, None], min_len, max_len).expect("brute set")
    }

    fn collect(text: &str, min_len: usize, max_len: usize, batch: usize) -> Vec<Vec<u8>> {
        let mut source = set(text, min_len, max_len)
            .into_source(0)
            .expect("brute source");
        let mut candidates = Vec::new();
        while let Some(next) = source.next_batch(batch).expect("batch") {
            candidates.extend(next.candidates);
        }
        candidates
    }

    fn rendered(candidates: &[Vec<u8>]) -> Vec<String> {
        candidates
            .iter()
            .map(|candidate| String::from_utf8_lossy(candidate).to_string())
            .collect()
    }

    #[test]
    fn parses_charset_and_counts_each_length() {
        let spec = BruteSpec::parse("?d", &[None, None, None, None], 1, 3).expect("parse");
        assert_eq!(spec.charset(), b"0123456789");
        assert_eq!(spec.per_len(), &[10, 100, 1000]);
        assert_eq!(spec.keyspace(), 1110);
        assert_eq!(spec.min_len(), 1);
        assert_eq!(spec.max_len(), 3);
        assert_eq!(spec.source_text(), "?d");
    }

    #[test]
    fn expands_custom_sets_and_dedupes_literals() {
        let custom_sets = [Some(b"ab".to_vec()), None, None, None];
        let spec = BruteSpec::parse("?1a", &custom_sets, 1, 2).expect("parse");
        assert_eq!(spec.charset(), b"ab");
        assert_eq!(spec.keyspace(), 2 + 4);
    }

    #[test]
    fn min_length_skips_shorter_candidates() {
        let set = set("?d", 2, 3);
        assert_eq!(set.keyspace(), 100 + 1000);
        let candidates = collect("?d", 2, 3, 500);
        assert_eq!(candidates.len(), 1100);
        assert_eq!(candidates[0], b"00");
        assert_eq!(candidates[99], b"99");
        assert_eq!(candidates[100], b"000");
    }

    #[test]
    fn single_character_charset_works_up_to_the_length_limit() {
        let spec = BruteSpec::parse("a", &[None, None, None, None], 1, 3).expect("parse");
        assert_eq!(spec.per_len(), &[1, 1, 1]);
        assert_eq!(spec.keyspace(), 3);
        assert_eq!(rendered(&collect("a", 1, 3, 2)), vec!["a", "aa", "aaa"]);

        let mut source = set("a", MAX_BRUTE_LENGTH, MAX_BRUTE_LENGTH)
            .into_source(0)
            .expect("source");
        let batch = source.next_batch(10).expect("batch").expect("some");
        assert_eq!(batch.candidates.len(), 1);
        assert_eq!(batch.candidates[0].len(), MAX_BRUTE_LENGTH);
        assert!(batch.candidates[0].iter().all(|byte| *byte == b'a'));
    }

    #[test]
    fn rejects_keyspace_above_u128() {
        let error = BruteSpec::parse("?a", &[None, None, None, None], 1, 20)
            .expect_err("95^20 exceeds u128");
        assert!(error.to_string().contains("u128"), "{error}");
    }

    #[test]
    fn rejects_invalid_length_ranges_and_charsets() {
        let none = [None, None, None, None];
        assert!(BruteSpec::parse("?d", &none, 0, 1).is_err());
        assert!(BruteSpec::parse("?d", &none, 3, 2).is_err());
        assert!(BruteSpec::parse("?d", &none, 1, MAX_BRUTE_LENGTH + 1).is_err());
        assert!(BruteSpec::parse("", &none, 1, 1).is_err());
        assert!(BruteSpec::parse("?b", &none, 1, 1).is_err());
        assert!(BruteSpec::parse("?1", &none, 1, 1).is_err());
        assert!(BruteSpec::parse("é", &none, 1, 1).is_err());
        assert!(BruteSpec::parse("abc?", &none, 1, 1).is_err());
    }

    #[test]
    fn rejects_recursive_custom_charset() {
        let error = BruteSet::parse("?1", &custom([Some("?1"), None, None, None]), 1, 1)
            .expect_err("recursion must fail");
        assert!(error.to_string().contains("?1"), "{error}");
    }

    #[test]
    fn enumerates_shortest_first_in_odometer_order() {
        let candidates = collect("ab", 1, 2, 3);
        assert_eq!(
            rendered(&candidates),
            vec!["a", "b", "aa", "ab", "ba", "bb"]
        );
    }

    #[test]
    fn batches_are_contiguous_and_cover_every_candidate_once() {
        let mut source = set("ab", 1, 3).into_source(0).expect("source");
        let mut expected_start = 0usize;
        let mut all = Vec::new();
        while let Some(batch) = source.next_batch(3).expect("batch") {
            assert_eq!(batch.start_index, expected_start);
            expected_start += batch.candidates.len();
            all.extend(batch.candidates);
        }
        assert_eq!(all.len(), 2 + 4 + 8);
        let unique: std::collections::BTreeSet<_> = all.iter().cloned().collect();
        assert_eq!(unique.len(), all.len());
        assert_eq!(all[0], b"a");
        assert_eq!(all[1], b"b");
        assert_eq!(all[2], b"aa");
        assert_eq!(all[all.len() - 1], b"bbb");
    }

    #[test]
    fn resume_matches_the_suffix_at_every_index() {
        let full = collect("abc", 1, 2, 5);
        let total = full.len();
        assert_eq!(total, 3 + 9);
        for start in 0..=total {
            let mut source = set("abc", 1, 2).into_source(start).expect("source");
            let mut seen = Vec::new();
            while let Some(batch) = source.next_batch(4).expect("batch") {
                seen.extend(batch.candidates);
            }
            assert_eq!(seen, full[start..], "resume at {start}");
        }
    }

    #[test]
    fn resume_at_a_length_boundary_starts_at_the_next_length() {
        // Charset "ab": length 1 is 2 candidates, length 2 is 4 candidates.
        let mut source = set("ab", 1, 2).into_source(2).expect("source");
        let batch = source.next_batch(1).expect("batch").expect("some");
        assert_eq!(batch.start_index, 2);
        assert_eq!(batch.candidates[0], b"aa");
    }

    #[test]
    fn source_rejects_start_past_total() {
        assert!(set("ab", 1, 1).into_source(3).is_err());
        let mut at_end = set("ab", 1, 1).into_source(2).expect("source at end");
        assert!(at_end.next_batch(1).expect("batch").is_none());
    }

    #[test]
    fn one_million_candidates_are_produced_without_error() {
        // 10 + 100 + ... + 1,000,000 = 1,111,110 candidates.
        let set = set("?d", 1, 6);
        assert_eq!(set.keyspace(), 1_111_110);
        let mut source = set.into_source(0).expect("source");
        let mut total = 0usize;
        let mut last = Vec::new();
        while let Some(batch) = source.next_batch(4096).expect("batch") {
            total += batch.candidates.len();
            last = batch.candidates.last().cloned().unwrap_or_default();
        }
        assert_eq!(total, 1_111_110);
        assert_eq!(last, b"999999");
    }

    #[test]
    fn estimate_warns_and_refuses_keyspaces_above_usize() {
        let estimate = set("?a", 1, 10).estimate(1);
        assert!(estimate.keyspace > usize::MAX as u128);
        assert!(!estimate.fits_usize);
        assert!(estimate
            .warnings
            .iter()
            .any(|warning| matches!(warning, BruteWarning::TooLargeToRun { .. })));
        assert!(set("?a", 1, 10).into_source(0).is_err());
    }

    #[test]
    fn estimate_warns_for_large_keyspace_and_long_lengths() {
        let estimate = set("?d?l", 1, 8).estimate(1);
        assert!(estimate.fits_usize);
        assert!(estimate
            .warnings
            .iter()
            .any(|warning| matches!(warning, BruteWarning::LargeKeyspace { .. })));

        let long = set("ab", 17, 17).estimate(1);
        assert!(long
            .warnings
            .iter()
            .any(|warning| matches!(warning, BruteWarning::LongLength { .. })));
    }

    #[test]
    fn signature_changes_with_charset_or_lengths() {
        let base = set("?d", 1, 2).signature().to_string();
        assert_eq!(base, set("?d", 1, 2).signature());
        assert_ne!(base, set("?l", 1, 2).signature());
        assert_ne!(base, set("?d", 1, 3).signature());
        assert_ne!(base, set("?d", 2, 2).signature());

        let custom_a = BruteSet::parse("?1", &custom([Some("ab"), None, None, None]), 1, 2)
            .expect("set")
            .signature()
            .to_string();
        let custom_b = BruteSet::parse("?1", &custom([Some("ba"), None, None, None]), 1, 2)
            .expect("set")
            .signature()
            .to_string();
        assert_ne!(custom_a, custom_b);
    }
}
