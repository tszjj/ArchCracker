// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

//! W2-002 mask candidate source.
//!
//! A mask is a fixed-length sequence of positions. Every position is either a
//! literal ASCII byte or a non-empty byte set. Candidates are generated in
//! odometer order, one batch at a time; the full keyspace is never materialised.

use crate::candidates::{CandidateBatch, CandidateSource};
use crate::error::{AcxError, Result};
use crate::estimate::{estimate_space, SpaceEstimate, SpaceInput};
use sha2::{Digest, Sha256};

pub const MAX_MASK_POSITIONS: usize = 128;
pub const MAX_MASK_EXPRESSION_BYTES: usize = 512;
pub const MAX_CUSTOM_CHARSET_BYTES: usize = 256;
pub const RECOMMENDED_MASK_POSITIONS: usize = 16;
pub const LARGE_KEYSPACE_WARNING: u128 = 1u128 << 32;

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b" !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

#[derive(Debug, Clone, PartialEq, Eq)]
enum MaskPosition {
    Literal(u8),
    Charset(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaskSpec {
    source_text: String,
    positions: Vec<MaskPosition>,
    keyspace: u128,
}

impl MaskSpec {
    /// Parse one fixed-length mask. `custom` contains the already-expanded
    /// `?1..?4` sets; `None` means that set is undefined.
    pub fn parse(text: &str, custom: &[Option<Vec<u8>>; 4]) -> Result<Self> {
        if text.is_empty() {
            return Err(AcxError::Attack("mask is empty".to_string()));
        }
        if text.trim().is_empty() {
            return Err(AcxError::Attack("mask is whitespace-only".to_string()));
        }
        if text.len() > MAX_MASK_EXPRESSION_BYTES {
            return Err(AcxError::Attack(format!(
                "mask is {} bytes; maximum expression length is {MAX_MASK_EXPRESSION_BYTES}",
                text.len()
            )));
        }

        let mut positions = Vec::new();
        let mut chars = text.chars();
        while let Some(ch) = chars.next() {
            if positions.len() >= MAX_MASK_POSITIONS {
                return Err(AcxError::Attack(format!(
                    "mask has more than {MAX_MASK_POSITIONS} positions"
                )));
            }
            if ch != '?' {
                if !ch.is_ascii() || !(0x20..=0x7e).contains(&(ch as u32)) {
                    return Err(AcxError::Attack(format!(
                        "mask literal {ch:?} is not printable ASCII"
                    )));
                }
                positions.push(MaskPosition::Literal(ch as u8));
                continue;
            }

            let Some(token) = chars.next() else {
                return Err(AcxError::Attack(
                    "mask ends with an unescaped `?`".to_string(),
                ));
            };
            let set = match token {
                '?' => vec![b'?'],
                'd' => DIGITS.to_vec(),
                'l' => LOWER.to_vec(),
                'u' => UPPER.to_vec(),
                's' => SYMBOLS.to_vec(),
                'a' => {
                    let mut all = Vec::with_capacity(95);
                    all.extend_from_slice(LOWER);
                    all.extend_from_slice(UPPER);
                    all.extend_from_slice(DIGITS);
                    all.extend_from_slice(SYMBOLS);
                    all
                }
                '1'..='4' => {
                    let index = (token as u8 - b'1') as usize;
                    custom[index].clone().ok_or_else(|| {
                        AcxError::Attack(format!("custom charset ?{token} is not defined"))
                    })?
                }
                other => return Err(AcxError::Attack(format!("unknown mask token `?{other}`"))),
            };
            if set.is_empty() {
                return Err(AcxError::Attack(format!(
                    "mask token `?{token}` expands to an empty charset"
                )));
            }
            positions.push(MaskPosition::Charset(set));
        }

        let mut keyspace = 1u128;
        for position in &positions {
            let radix = match position {
                MaskPosition::Literal(_) => 1u128,
                MaskPosition::Charset(set) => set.len() as u128,
            };
            keyspace = keyspace
                .checked_mul(radix)
                .ok_or_else(|| AcxError::Attack("mask keyspace exceeds u128".to_string()))?;
        }

        Ok(Self {
            source_text: text.to_string(),
            positions,
            keyspace,
        })
    }

    pub fn source_text(&self) -> &str {
        &self.source_text
    }

    pub fn keyspace(&self) -> u128 {
        self.keyspace
    }

    pub fn positions(&self) -> usize {
        self.positions.len()
    }

    /// Render the candidate at `index` in odometer order. Used by the hybrid
    /// affix generator; mask mode itself uses [`MaskCursor`].
    pub(crate) fn candidate_at(&self, index: usize) -> Result<Vec<u8>> {
        if index as u128 >= self.keyspace {
            return Err(AcxError::Attack(format!(
                "affix index {index} exceeds mask keyspace {}",
                self.keyspace
            )));
        }
        let mut digits = vec![0usize; self.positions.len()];
        let mut value = index;
        for (offset, position) in self.positions.iter().enumerate().rev() {
            let radix = match position {
                MaskPosition::Literal(_) => 1,
                MaskPosition::Charset(set) => set.len(),
            };
            digits[offset] = value % radix;
            value /= radix;
        }
        let mut output = Vec::with_capacity(self.positions.len());
        for (position, digit) in self.positions.iter().zip(digits) {
            match position {
                MaskPosition::Literal(byte) => output.push(*byte),
                MaskPosition::Charset(set) => output.push(set[digit]),
            }
        }
        Ok(output)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaskWarning {
    LongMask {
        positions: usize,
        recommended: usize,
    },
    LargeKeyspace {
        keyspace: u128,
        threshold: u128,
    },
    TooLargeToRun {
        keyspace: u128,
        max: u128,
    },
}

impl std::fmt::Display for MaskWarning {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LongMask {
                positions,
                recommended,
            } => write!(
                formatter,
                "mask has {positions} positions; recommended maximum is {recommended}"
            ),
            Self::LargeKeyspace {
                keyspace,
                threshold,
            } => write!(
                formatter,
                "mask keyspace {keyspace} exceeds warning threshold {threshold}"
            ),
            Self::TooLargeToRun {
                keyspace,
                max,
            } => write!(
                formatter,
                "mask keyspace {keyspace} exceeds executable limit {max}; only estimation is possible"
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaskEstimate {
    pub keyspace: u128,
    pub fits_usize: bool,
    pub warnings: Vec<MaskWarning>,
    pub per_mask: Vec<u128>,
    /// Core-side memory estimate for `--estimate` and the pre-attack summary.
    pub space: SpaceEstimate,
}

#[derive(Debug, Clone)]
pub struct MaskSet {
    masks: Vec<MaskSpec>,
    keyspace: u128,
    signature: String,
}

impl MaskSet {
    pub fn parse(masks: &[String], custom_texts: &[Option<String>; 4]) -> Result<Self> {
        if masks.is_empty() {
            return Err(AcxError::Attack("no --mask provided".to_string()));
        }

        let custom_sets = parse_custom_sets(custom_texts)?;

        let mut parsed = Vec::with_capacity(masks.len());
        let mut keyspace = 0u128;
        for mask in masks {
            let spec = MaskSpec::parse(mask, &custom_sets)?;
            keyspace = keyspace
                .checked_add(spec.keyspace())
                .ok_or_else(|| AcxError::Attack("mask total keyspace exceeds u128".to_string()))?;
            parsed.push(spec);
        }

        let signature = mask_signature(masks, custom_texts);
        Ok(Self {
            masks: parsed,
            keyspace,
            signature,
        })
    }

    pub fn keyspace(&self) -> u128 {
        self.keyspace
    }

    pub fn signature(&self) -> &str {
        &self.signature
    }

    pub fn estimate(&self, threads: usize) -> MaskEstimate {
        let fits_usize = self.keyspace <= usize::MAX as u128;
        let mut warnings = Vec::new();
        for mask in &self.masks {
            if mask.positions() > RECOMMENDED_MASK_POSITIONS {
                warnings.push(MaskWarning::LongMask {
                    positions: mask.positions(),
                    recommended: RECOMMENDED_MASK_POSITIONS,
                });
            }
        }
        if self.keyspace > LARGE_KEYSPACE_WARNING {
            warnings.push(MaskWarning::LargeKeyspace {
                keyspace: self.keyspace,
                threshold: LARGE_KEYSPACE_WARNING,
            });
        }
        if !fits_usize {
            warnings.push(MaskWarning::TooLargeToRun {
                keyspace: self.keyspace,
                max: usize::MAX as u128,
            });
        }
        let max_positions = self
            .masks
            .iter()
            .map(MaskSpec::positions)
            .max()
            .unwrap_or(0);
        let space = estimate_space(&SpaceInput {
            total: self.keyspace,
            threads,
            max_candidate_bytes: max_positions as u128,
            batch_bytes_cap: None,
            source_bytes: 4096,
        });
        MaskEstimate {
            keyspace: self.keyspace,
            fits_usize,
            warnings,
            per_mask: self.masks.iter().map(MaskSpec::keyspace).collect(),
            space,
        }
    }

    /// Turn the set into a scheduler source starting at a global candidate
    /// index. The source rejects keyspaces that do not fit the W1 `usize`
    /// index contract.
    pub fn into_source(self, start_index: usize) -> Result<MaskSource> {
        let total = usize::try_from(self.keyspace).map_err(|_| {
            AcxError::Attack(format!(
                "mask keyspace {} exceeds executable limit {}",
                self.keyspace,
                usize::MAX
            ))
        })?;
        if start_index > total {
            return Err(AcxError::Attack(format!(
                "mask resume index {start_index} exceeds total {total}"
            )));
        }

        let mut remaining = start_index;
        let mut cursors = Vec::with_capacity(self.masks.len());
        let mut selected = false;
        for spec in self.masks {
            let keyspace = usize::try_from(spec.keyspace()).map_err(|_| {
                AcxError::Attack("individual mask keyspace exceeds usize".to_string())
            })?;
            if !selected && remaining < keyspace {
                cursors.push(Some(MaskCursor::new(spec, remaining)?));
                selected = true;
            } else if selected {
                cursors.push(Some(MaskCursor::new(spec, 0)?));
            } else {
                remaining -= keyspace;
                cursors.push(None);
            }
        }
        let current = if selected {
            cursors
                .iter()
                .position(Option::is_some)
                .expect("selected mask exists")
        } else {
            // Start at the end of the source; `next_batch` returns None.
            cursors.len()
        };
        Ok(MaskSource {
            cursors,
            current,
            next_index: start_index,
            total,
        })
    }
}

/// Parse the four `--custom-charsetN` definitions. Definitions may contain
/// built-in tokens and literals but cannot reference `?1..?4` (no recursion).
pub(crate) fn parse_custom_sets(
    custom_texts: &[Option<String>; 4],
) -> Result<[Option<Vec<u8>>; 4]> {
    let mut sets: [Option<Vec<u8>>; 4] = Default::default();
    for (index, text) in custom_texts.iter().enumerate() {
        if let Some(text) = text {
            sets[index] = Some(parse_charset_expression(text)?);
        }
    }
    Ok(sets)
}

/// Expand one charset expression; `?1..?4` are rejected because no custom sets
/// are supplied (used for the `--custom-charsetN` definitions themselves).
pub(crate) fn parse_charset_expression(text: &str) -> Result<Vec<u8>> {
    expand_charset(text, None)
}

/// Expand one charset expression, resolving `?1..?4` against `custom`. Used by
/// the W2-003 brute source; order is preserved and duplicates are removed.
pub(crate) fn expand_charset_with(text: &str, custom: &[Option<Vec<u8>>; 4]) -> Result<Vec<u8>> {
    expand_charset(text, Some(custom))
}

fn expand_charset(text: &str, custom: Option<&[Option<Vec<u8>>; 4]>) -> Result<Vec<u8>> {
    if text.is_empty() {
        return Err(AcxError::Attack("charset expression is empty".to_string()));
    }
    let mut output = Vec::new();
    let mut chars = text.chars();
    while let Some(ch) = chars.next() {
        if ch != '?' {
            if !ch.is_ascii() || !(0x20..=0x7e).contains(&(ch as u32)) {
                return Err(AcxError::Attack(format!(
                    "charset literal {ch:?} is not printable ASCII"
                )));
            }
            push_unique(&mut output, ch as u8);
            continue;
        }
        let Some(token) = chars.next() else {
            return Err(AcxError::Attack(
                "charset expression ends with an unescaped `?`".to_string(),
            ));
        };
        match token {
            '?' => push_unique(&mut output, b'?'),
            'd' => extend_unique(&mut output, DIGITS),
            'l' => extend_unique(&mut output, LOWER),
            'u' => extend_unique(&mut output, UPPER),
            's' => extend_unique(&mut output, SYMBOLS),
            'a' => {
                extend_unique(&mut output, LOWER);
                extend_unique(&mut output, UPPER);
                extend_unique(&mut output, DIGITS);
                extend_unique(&mut output, SYMBOLS);
            }
            '1'..='4' => {
                let index = (token as u8 - b'1') as usize;
                match custom.and_then(|sets| sets[index].as_ref()) {
                    Some(set) => extend_unique(&mut output, set),
                    None if custom.is_some() => {
                        return Err(AcxError::Attack(format!(
                            "custom charset ?{token} is not defined"
                        )))
                    }
                    None => {
                        return Err(AcxError::Attack(format!(
                            "custom charset cannot reference `?{token}`"
                        )))
                    }
                }
            }
            other => {
                return Err(AcxError::Attack(format!(
                    "unknown charset token `?{other}`"
                )))
            }
        }
        check_charset_len(&output)?;
    }
    if output.is_empty() {
        return Err(AcxError::Attack(
            "charset is empty after expansion".to_string(),
        ));
    }
    check_charset_len(&output)?;
    Ok(output)
}

fn check_charset_len(output: &[u8]) -> Result<()> {
    if output.len() > MAX_CUSTOM_CHARSET_BYTES {
        return Err(AcxError::Attack(format!(
            "charset exceeds {MAX_CUSTOM_CHARSET_BYTES} bytes"
        )));
    }
    Ok(())
}

fn extend_unique(output: &mut Vec<u8>, bytes: &[u8]) {
    for byte in bytes {
        push_unique(output, *byte);
    }
}

fn push_unique(output: &mut Vec<u8>, byte: u8) {
    if !output.contains(&byte) {
        output.push(byte);
    }
}

fn mask_signature(masks: &[String], custom: &[Option<String>; 4]) -> String {
    let mut material = String::from("mask\n");
    for (index, text) in custom.iter().enumerate() {
        material.push_str(&format!(
            "custom{index}={}\n",
            text.as_deref().unwrap_or("")
        ));
    }
    for mask in masks {
        material.push_str(&format!("mask={mask}\n"));
    }
    hex_sha256(material.as_bytes())
}

pub(crate) fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

#[derive(Debug)]
struct MaskCursor {
    spec: MaskSpec,
    radices: Vec<usize>,
    digits: Vec<usize>,
}

impl MaskCursor {
    fn new(spec: MaskSpec, local_index: usize) -> Result<Self> {
        let radices: Vec<usize> = spec
            .positions
            .iter()
            .map(|position| match position {
                MaskPosition::Literal(_) => 1,
                MaskPosition::Charset(set) => set.len(),
            })
            .collect();
        let mut digits = vec![0usize; radices.len()];
        let mut value = local_index;
        for (index, radix) in radices.iter().enumerate().rev() {
            digits[index] = value % radix;
            value /= radix;
        }
        if value != 0 {
            return Err(AcxError::Attack(
                "mask resume index exceeds its keyspace".to_string(),
            ));
        }
        Ok(Self {
            spec,
            radices,
            digits,
        })
    }

    fn candidate(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(self.spec.positions.len());
        for (position, digit) in self.spec.positions.iter().zip(&self.digits) {
            match position {
                MaskPosition::Literal(byte) => output.push(*byte),
                MaskPosition::Charset(set) => output.push(set[*digit]),
            }
        }
        output
    }

    fn advance(&mut self) -> bool {
        for index in (0..self.radices.len()).rev() {
            self.digits[index] += 1;
            if self.digits[index] < self.radices[index] {
                return true;
            }
            self.digits[index] = 0;
        }
        false
    }
}

pub struct MaskSource {
    cursors: Vec<Option<MaskCursor>>,
    current: usize,
    next_index: usize,
    total: usize,
}

impl CandidateSource for MaskSource {
    fn total(&self) -> usize {
        self.total
    }

    fn next_batch(&mut self, max: usize) -> Result<Option<CandidateBatch>> {
        if max == 0 || self.next_index >= self.total {
            return Ok(None);
        }
        let start_index = self.next_index;
        let mut candidates = Vec::with_capacity(max.min(self.total - self.next_index));
        while candidates.len() < max {
            let Some(cursor) = self.cursors.get_mut(self.current).and_then(Option::as_mut) else {
                break;
            };
            candidates.push(cursor.candidate());
            self.next_index += 1;
            if !cursor.advance() {
                self.current += 1;
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

    fn empty_custom() -> [Option<Vec<u8>>; 4] {
        [None, None, None, None]
    }

    #[test]
    fn parses_known_mask_and_keyspace() {
        let mask = MaskSpec::parse("?u?l?l?d?d", &empty_custom()).expect("parse");
        assert_eq!(mask.positions(), 5);
        assert_eq!(mask.keyspace(), 26 * 26 * 26 * 10 * 10);
        assert_eq!(mask.source_text(), "?u?l?l?d?d");
        assert_eq!(
            MaskSpec::parse("?a", &empty_custom())
                .expect("?a")
                .keyspace(),
            95
        );
        assert_eq!(
            MaskSpec::parse("?s", &empty_custom())
                .expect("?s")
                .keyspace(),
            33
        );
    }

    #[test]
    fn parses_escape_and_custom_sets() {
        let custom_sets = [Some(vec![b'a', b'b']), None, None, None];
        let mask = MaskSpec::parse("??-?1?1", &custom_sets).expect("parse");
        assert_eq!(mask.keyspace(), 4);
        let mut source = MaskSet::parse(
            &["??-?1?1".to_string()],
            &custom([Some("ab"), None, None, None]),
        )
        .expect("set")
        .into_source(0)
        .expect("source");
        let batch = source.next_batch(10).expect("batch").expect("some");
        let rendered: Vec<String> = batch
            .candidates
            .iter()
            .map(|candidate| String::from_utf8_lossy(candidate).to_string())
            .collect();
        assert_eq!(rendered, vec!["?-aa", "?-ab", "?-ba", "?-bb"]);
    }

    #[test]
    fn rejects_bad_masks() {
        for mask in ["", "abc?", "?x", "?1", " ", "   "] {
            let result = MaskSpec::parse(mask, &empty_custom());
            assert!(result.is_err(), "mask {mask:?} must fail");
        }
        assert!(MaskSpec::parse(&"a".repeat(MAX_MASK_POSITIONS + 1), &empty_custom()).is_err());
    }

    #[test]
    fn source_handles_mask_boundaries_and_resume() {
        let set = MaskSet::parse(
            &["?d".to_string(), "?l".to_string()],
            &[None, None, None, None],
        )
        .expect("set");
        assert_eq!(set.estimate(1).keyspace, 36);
        let mut source = set.into_source(9).expect("source");
        let first = source.next_batch(3).expect("batch").expect("some");
        assert_eq!(first.start_index, 9);
        assert_eq!(first.candidates.len(), 3);
        assert_eq!(String::from_utf8_lossy(&first.candidates[0]), "9");
        assert_eq!(String::from_utf8_lossy(&first.candidates[1]), "a");
        assert_eq!(String::from_utf8_lossy(&first.candidates[2]), "b");

        let set = MaskSet::parse(
            &["?d".to_string(), "?l".to_string()],
            &[None, None, None, None],
        )
        .expect("set");
        let mut boundary = set.into_source(10).expect("boundary source");
        let batch = boundary.next_batch(1).expect("batch").expect("some");
        assert_eq!(String::from_utf8_lossy(&batch.candidates[0]), "a");
        let mut end = MaskSet::parse(
            &["?d".to_string(), "?l".to_string()],
            &[None, None, None, None],
        )
        .expect("set")
        .into_source(36)
        .expect("end source");
        assert!(end.next_batch(1).expect("end batch").is_none());
        assert!(
            MaskSet::parse(&["?d".to_string()], &[None, None, None, None],)
                .expect("set")
                .into_source(11)
                .is_err()
        );
    }

    #[test]
    fn source_covers_every_candidate_once() {
        let set = MaskSet::parse(
            &["?d".to_string(), "?l".to_string()],
            &[None, None, None, None],
        )
        .expect("set");
        let mut source = set.into_source(0).expect("source");
        let mut seen = Vec::new();
        while let Some(batch) = source.next_batch(7).expect("batch") {
            seen.extend(batch.candidates);
        }
        assert_eq!(seen.len(), 36);
        let unique: std::collections::BTreeSet<_> = seen.iter().cloned().collect();
        assert_eq!(unique.len(), 36);
        assert_eq!(seen[0], b"0");
        assert_eq!(seen[9], b"9");
        assert_eq!(seen[10], b"a");
        assert_eq!(seen[35], b"z");
    }

    #[test]
    fn estimate_warns_for_long_and_large_masks() {
        let mask = "?a".repeat(10);
        let set = MaskSet::parse(&[mask], &[None, None, None, None]).expect("set");
        let estimate = set.estimate(1);
        assert!(!estimate.fits_usize);
        assert!(estimate
            .warnings
            .iter()
            .any(|warning| matches!(warning, MaskWarning::TooLargeToRun { .. })));
        assert!(set.into_source(0).is_err());
    }
}
