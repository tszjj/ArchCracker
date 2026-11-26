// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

//! W2-004 hybrid candidate source: dictionary word × (rule chain | affix mask).
//!
//! The dictionary is the outer loop and the variant index the inner loop:
//! `index = dict_line * V + variant_index`. Reading is streaming, so only the
//! current word and the current batch are resident. `V` is fixed for every
//! line, which keeps the global index a stable checkpoint watermark.
//!
//! Variant order is: every `--rule` in CLI order, then one combined affix
//! generator (`prefix + word + suffix`, suffix mask fastest) when
//! `--prefix-mask`/`--suffix-mask` is supplied.

use crate::candidates::dictionary::{scan_dictionary, DictionaryScan, LineReader};
use crate::candidates::mask::{hex_sha256, parse_custom_sets, MaskSpec};
use crate::candidates::rules::RuleChain;
use crate::candidates::{CandidateBatch, CandidateSource, MAX_BATCH_BYTES};
use crate::error::{AcxError, Result};
use crate::estimate::{estimate_space, SpaceEstimate, SpaceInput};
use encoding_rs::Encoding;
use std::path::{Path, PathBuf};

/// Source-owned buffers: reader chunk + pending line + held line + charset sets.
const HYBRID_SOURCE_BYTES: u128 = 2 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct HybridSpec {
    dictionary: PathBuf,
    force: Option<&'static Encoding>,
    scan: DictionaryScan,
    rules: Vec<RuleChain>,
    prefix: Option<MaskSpec>,
    suffix: Option<MaskSpec>,
    suffix_keyspace: usize,
    variants_per_line: usize,
    total: Option<usize>,
    total_u128: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HybridWarning {
    TooLargeToRun { total: u128, max: u128 },
}

impl std::fmt::Display for HybridWarning {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLargeToRun { total, max } => write!(
                formatter,
                "hybrid total {total} exceeds executable limit {max}; only estimation is possible"
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HybridEstimate {
    pub dict_lines: usize,
    pub variants_per_line: usize,
    pub total: u128,
    pub fits_usize: bool,
    pub space: SpaceEstimate,
    pub warnings: Vec<HybridWarning>,
}

#[derive(Debug, Clone)]
pub struct HybridSet {
    spec: HybridSpec,
    signature: String,
}

impl HybridSet {
    pub fn parse(
        dictionary: &Path,
        rule_texts: &[String],
        prefix_text: Option<&str>,
        suffix_text: Option<&str>,
        custom_texts: &[Option<String>; 4],
    ) -> Result<Self> {
        let custom_sets = parse_custom_sets(custom_texts)?;
        let rules = if rule_texts.is_empty() {
            vec![RuleChain::identity()]
        } else {
            rule_texts
                .iter()
                .map(|text| RuleChain::parse(text))
                .collect::<Result<Vec<_>>>()?
        };
        let prefix = prefix_text
            .map(|text| MaskSpec::parse(text, &custom_sets))
            .transpose()?;
        let suffix = suffix_text
            .map(|text| MaskSpec::parse(text, &custom_sets))
            .transpose()?;

        let prefix_keyspace = match &prefix {
            Some(mask) => mask.keyspace_usize()?,
            None => 1,
        };
        let suffix_keyspace = match &suffix {
            Some(mask) => mask.keyspace_usize()?,
            None => 1,
        };
        let affix_keyspace = if prefix.is_none() && suffix.is_none() {
            0
        } else {
            prefix_keyspace
                .checked_mul(suffix_keyspace)
                .ok_or_else(|| {
                    AcxError::Attack(
                        "affix keyspace exceeds the executable usize limit".to_string(),
                    )
                })?
        };
        let variants_per_line = rules.len().checked_add(affix_keyspace).ok_or_else(|| {
            AcxError::Attack("variants per line exceed the executable usize limit".to_string())
        })?;
        let scan = scan_dictionary(dictionary)?;
        let total_u128 = (scan.lines as u128) * (variants_per_line as u128);
        let total = usize::try_from(total_u128).ok();

        let signature = hybrid_signature(&rules, prefix_text, suffix_text, custom_texts);
        Ok(Self {
            spec: HybridSpec {
                dictionary: dictionary.to_path_buf(),
                force: scan.force,
                scan,
                rules,
                prefix,
                suffix,
                suffix_keyspace,
                variants_per_line,
                total,
                total_u128,
            },
            signature,
        })
    }

    pub fn dict_lines(&self) -> usize {
        self.spec.scan.lines
    }

    pub fn variants_per_line(&self) -> usize {
        self.spec.variants_per_line
    }

    pub fn total_u128(&self) -> u128 {
        self.spec.total_u128
    }

    pub fn signature(&self) -> &str {
        &self.signature
    }

    pub fn estimate(&self, threads: usize) -> HybridEstimate {
        let max_line = self.spec.scan.max_line_bytes as u128;
        let max_rule_growth = self
            .spec
            .rules
            .iter()
            .map(RuleChain::max_added_bytes)
            .max()
            .unwrap_or(0) as u128;
        let affix_positions = self.spec.prefix.as_ref().map_or(0, MaskSpec::positions)
            + self.spec.suffix.as_ref().map_or(0, MaskSpec::positions);
        let space = estimate_space(&SpaceInput {
            total: self.spec.total_u128,
            threads,
            max_candidate_bytes: max_line + max_rule_growth.max(affix_positions as u128),
            batch_bytes_cap: Some(MAX_BATCH_BYTES as u128),
            source_bytes: HYBRID_SOURCE_BYTES + 2 * max_line,
        });
        let fits_usize = self.spec.total.is_some();
        let mut warnings = Vec::new();
        if !fits_usize {
            warnings.push(HybridWarning::TooLargeToRun {
                total: self.spec.total_u128,
                max: usize::MAX as u128,
            });
        }
        HybridEstimate {
            dict_lines: self.spec.scan.lines,
            variants_per_line: self.spec.variants_per_line,
            total: self.spec.total_u128,
            fits_usize,
            space,
            warnings,
        }
    }

    pub fn into_source(self, start_index: usize) -> Result<HybridSource> {
        HybridSource::new(self.spec, start_index)
    }
}

fn hybrid_signature(
    rules: &[RuleChain],
    prefix: Option<&str>,
    suffix: Option<&str>,
    custom: &[Option<String>; 4],
) -> String {
    let mut material = String::from("hybrid\n");
    for (index, rule) in rules.iter().enumerate() {
        material.push_str(&format!("rule[{index}]={}\n", rule.text()));
    }
    material.push_str(&format!("prefix={}\n", prefix.unwrap_or("")));
    material.push_str(&format!("suffix={}\n", suffix.unwrap_or("")));
    for (index, text) in custom.iter().enumerate() {
        material.push_str(&format!(
            "custom{index}={}\n",
            text.as_deref().unwrap_or("")
        ));
    }
    hex_sha256(material.as_bytes())
}

pub struct HybridSource {
    rules: Vec<RuleChain>,
    prefix: Option<MaskSpec>,
    suffix: Option<MaskSpec>,
    suffix_keyspace: usize,
    rules_len: usize,
    variants_per_line: usize,
    reader: Option<LineReader>,
    line: Vec<u8>,
    line_index: usize,
    dict_lines: usize,
    variant: usize,
    next_index: usize,
    total: usize,
}

impl HybridSource {
    fn new(spec: HybridSpec, start_index: usize) -> Result<Self> {
        let total = spec.total.ok_or_else(|| {
            AcxError::Attack(format!(
                "hybrid total {} exceeds executable limit {}",
                spec.total_u128,
                usize::MAX
            ))
        })?;
        if start_index > total {
            return Err(AcxError::Attack(format!(
                "hybrid resume index {start_index} exceeds total {total}"
            )));
        }
        if total == 0 {
            let rules_len = spec.rules.len();
            return Ok(Self {
                rules: spec.rules,
                prefix: spec.prefix,
                suffix: spec.suffix,
                suffix_keyspace: spec.suffix_keyspace,
                rules_len,
                variants_per_line: spec.variants_per_line,
                reader: None,
                line: Vec::new(),
                line_index: 0,
                dict_lines: spec.scan.lines,
                variant: 0,
                next_index: 0,
                total: 0,
            });
        }

        let variants_per_line = spec.variants_per_line;
        let dict_line = start_index / variants_per_line;
        let variant = start_index % variants_per_line;
        let rules_len = spec.rules.len();
        let mut source = Self {
            rules: spec.rules,
            prefix: spec.prefix,
            suffix: spec.suffix,
            suffix_keyspace: spec.suffix_keyspace,
            rules_len,
            variants_per_line,
            reader: None,
            line: Vec::new(),
            line_index: dict_line,
            dict_lines: spec.scan.lines,
            variant,
            next_index: start_index,
            total,
        };

        if start_index == total {
            source.line_index = source.dict_lines;
            return Ok(source);
        }

        let mut reader = LineReader::open(&spec.dictionary, spec.force)?;
        for _ in 0..dict_line {
            if reader.next_line()?.is_none() {
                return Err(AcxError::Dictionary(format!(
                    "dictionary ended while skipping to line {dict_line}"
                )));
            }
        }
        let line = reader.next_line()?.ok_or_else(|| {
            AcxError::Dictionary(format!(
                "dictionary ended at line {dict_line} before total {total}"
            ))
        })?;
        source.line = line.into_bytes();
        source.reader = Some(reader);
        Ok(source)
    }

    fn candidate(&self) -> Result<Vec<u8>> {
        if self.variant < self.rules_len {
            return Ok(self.rules[self.variant].apply(&self.line));
        }
        let local = self.variant - self.rules_len;
        let (prefix_index, suffix_index) = if self.prefix.is_some() && self.suffix.is_some() {
            (local / self.suffix_keyspace, local % self.suffix_keyspace)
        } else if self.prefix.is_some() {
            (local, 0)
        } else {
            (0, local)
        };
        let prefix = match &self.prefix {
            Some(mask) => mask.candidate_at(prefix_index)?,
            None => Vec::new(),
        };
        let suffix = match &self.suffix {
            Some(mask) => mask.candidate_at(suffix_index)?,
            None => Vec::new(),
        };
        let mut output = Vec::with_capacity(prefix.len() + self.line.len() + suffix.len());
        output.extend_from_slice(&prefix);
        output.extend_from_slice(&self.line);
        output.extend_from_slice(&suffix);
        Ok(output)
    }

    fn advance(&mut self) -> Result<()> {
        self.variant += 1;
        if self.variant < self.variants_per_line {
            return Ok(());
        }
        self.variant = 0;
        self.line_index += 1;
        if self.line_index >= self.dict_lines {
            self.reader = None;
            self.line.clear();
            return Ok(());
        }
        let next = self
            .reader
            .as_mut()
            .ok_or_else(|| {
                AcxError::Internal("hybrid source lost its dictionary reader".to_string())
            })?
            .next_line()?;
        match next {
            Some(line) => self.line = line.into_bytes(),
            None => {
                return Err(AcxError::Dictionary(format!(
                    "dictionary ended at line {} before total {}",
                    self.line_index, self.total
                )))
            }
        }
        Ok(())
    }
}

impl CandidateSource for HybridSource {
    fn total(&self) -> usize {
        self.total
    }

    fn next_batch(&mut self, max: usize) -> Result<Option<CandidateBatch>> {
        if max == 0 || self.next_index >= self.total {
            return Ok(None);
        }
        let start_index = self.next_index;
        let mut candidates = Vec::with_capacity(max.min(self.total - self.next_index));
        let mut bytes = 0usize;
        while candidates.len() < max && self.next_index < self.total {
            let candidate = self.candidate()?;
            let length = candidate.len();
            if !candidates.is_empty() && bytes.saturating_add(length) > MAX_BATCH_BYTES {
                break;
            }
            bytes += length;
            candidates.push(candidate);
            self.next_index += 1;
            self.advance()?;
        }
        if candidates.is_empty() {
            return Err(AcxError::Internal(
                "hybrid source produced an empty batch".to_string(),
            ));
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
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    /// Writable scratch directory inside the build tree. Some confined test
    /// harnesses deny writes under `%TEMP%`.
    fn scratch_dir() -> PathBuf {
        let mut path = std::env::current_exe().unwrap_or_default();
        if path.pop() {
            path.pop();
        }
        path.push("acx-test-tmp");
        std::fs::create_dir_all(&path).expect("create scratch dir");
        path
    }

    struct TempDictionary {
        path: PathBuf,
    }

    impl TempDictionary {
        fn new(contents: &str) -> Self {
            let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            let path = scratch_dir().join(format!("acx-hybrid-{}-{id}.txt", std::process::id()));
            std::fs::write(&path, contents).expect("write dictionary");
            Self { path }
        }
    }

    impl Drop for TempDictionary {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn set(
        dictionary: &Path,
        rules: &[&str],
        prefix: Option<&str>,
        suffix: Option<&str>,
    ) -> HybridSet {
        let rules: Vec<String> = rules.iter().map(|rule| (*rule).to_string()).collect();
        HybridSet::parse(
            dictionary,
            &rules,
            prefix,
            suffix,
            &[None, None, None, None],
        )
        .expect("hybrid set")
    }

    fn collect(set: HybridSet, batch: usize) -> Vec<Vec<u8>> {
        let mut source = set.into_source(0).expect("source");
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
    fn rules_then_affix_match_the_documented_order() {
        let dictionary = TempDictionary::new("acme\n");
        let set = set(
            &dictionary.path,
            &["identity", "capitalize|append:123"],
            None,
            Some("?d?d"),
        );
        assert_eq!(set.dict_lines(), 1);
        assert_eq!(set.variants_per_line(), 102);
        assert_eq!(set.total_u128(), 102);
        let candidates = collect(set, 7);
        assert_eq!(candidates.len(), 102);
        assert_eq!(candidates[0], b"acme");
        assert_eq!(candidates[1], b"Acme123");
        assert_eq!(candidates[2], b"acme00");
        assert_eq!(candidates[101], b"acme99");
    }

    #[test]
    fn prefix_and_suffix_combine_into_one_affix_generator() {
        let dictionary = TempDictionary::new("acme\n");
        let set = set(&dictionary.path, &["identity"], Some("X"), Some("?d"));
        assert_eq!(set.variants_per_line(), 1 + 10);
        let candidates = collect(set, 4);
        assert_eq!(candidates[0], b"acme");
        assert_eq!(candidates[1], b"Xacme0");
        assert_eq!(candidates[10], b"Xacme9");
    }

    #[test]
    fn defaults_to_identity_when_no_rule_is_given() {
        let dictionary = TempDictionary::new("one\ntwo\n");
        let set = set(&dictionary.path, &[], None, None);
        assert_eq!(set.variants_per_line(), 1);
        assert_eq!(rendered(&collect(set, 1)), vec!["one", "two"]);
    }

    #[test]
    fn resume_at_every_index_matches_the_suffix() {
        let dictionary = TempDictionary::new("one\ntwo\nthree\n");
        let full = collect(
            set(&dictionary.path, &["identity", "upper"], None, Some("?d")),
            5,
        );
        assert_eq!(full.len(), 3 * 12);
        for start in 0..=full.len() {
            let mut source = set(&dictionary.path, &["identity", "upper"], None, Some("?d"))
                .into_source(start)
                .expect("source");
            let mut seen = Vec::new();
            while let Some(batch) = source.next_batch(7).expect("batch") {
                seen.extend(batch.candidates);
            }
            assert_eq!(seen, full[start..], "resume at {start}");
        }
    }

    #[test]
    fn resume_at_a_line_boundary_starts_at_variant_zero() {
        let dictionary = TempDictionary::new("one\ntwo\n");
        let set = set(&dictionary.path, &["identity"], None, Some("?d"));
        // V = 1 + 10; the second line starts at index 11.
        let mut source = set.into_source(11).expect("source");
        let batch = source.next_batch(1).expect("batch").expect("some");
        assert_eq!(batch.start_index, 11);
        assert_eq!(batch.candidates[0], b"two");
    }

    #[test]
    fn changes_every_signature_input() {
        let dictionary = TempDictionary::new("word\n");
        let base = set(&dictionary.path, &["identity"], None, None)
            .signature()
            .to_string();
        assert_eq!(
            base,
            set(&dictionary.path, &["identity"], None, None).signature()
        );
        assert_ne!(
            base,
            set(&dictionary.path, &["lower"], None, None).signature()
        );
        assert_ne!(
            base,
            set(&dictionary.path, &["identity"], Some("x"), None).signature()
        );
        assert_ne!(
            base,
            set(&dictionary.path, &["identity"], None, Some("?d")).signature()
        );
    }

    #[test]
    fn estimate_reports_lines_variants_total_and_space() {
        let dictionary = TempDictionary::new("one\ntwo\nthree\n");
        let set = set(&dictionary.path, &["identity"], None, Some("?d"));
        let estimate = set.estimate(14);
        assert_eq!(estimate.dict_lines, 3);
        assert_eq!(estimate.variants_per_line, 11);
        assert_eq!(estimate.total, 33);
        assert!(estimate.fits_usize);
        assert_eq!(estimate.space.watermark_bytes, 33u128.div_ceil(8));
        assert_eq!(estimate.space.in_flight_batches, 17);
        assert!(estimate.warnings.is_empty());
    }
}
