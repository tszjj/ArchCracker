// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

//! W2-004 minimal rule chains.
//!
//! A rule chain is a fixed list of named transforms applied left to right to a
//! dictionary word. The syntax is deliberately small (`identity|lower|upper|
//! capitalize|toggle|reverse|append:<literal>|prepend:<literal>`) so the
//! signature stays stable and the parser stays auditable.

use crate::error::{AcxError, Result};

pub const MAX_RULE_LITERAL_BYTES: usize = 64;
pub const MAX_RULE_CHAIN_LENGTH: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transform {
    Identity,
    Lower,
    Upper,
    Capitalize,
    Toggle,
    Reverse,
    Append(Vec<u8>),
    Prepend(Vec<u8>),
}

impl Transform {
    fn apply(&self, word: &mut Vec<u8>) {
        match self {
            Self::Identity => {}
            Self::Lower => {
                for byte in word.iter_mut() {
                    *byte = byte.to_ascii_lowercase();
                }
            }
            Self::Upper => {
                for byte in word.iter_mut() {
                    *byte = byte.to_ascii_uppercase();
                }
            }
            Self::Capitalize => {
                for (index, byte) in word.iter_mut().enumerate() {
                    if index == 0 {
                        *byte = byte.to_ascii_uppercase();
                    } else {
                        *byte = byte.to_ascii_lowercase();
                    }
                }
            }
            Self::Toggle => {
                for byte in word.iter_mut() {
                    if byte.is_ascii_lowercase() {
                        *byte = byte.to_ascii_uppercase();
                    } else if byte.is_ascii_uppercase() {
                        *byte = byte.to_ascii_lowercase();
                    }
                }
            }
            Self::Reverse => word.reverse(),
            Self::Append(literal) => word.extend_from_slice(literal),
            Self::Prepend(literal) => {
                let mut output = Vec::with_capacity(literal.len() + word.len());
                output.extend_from_slice(literal);
                output.extend_from_slice(word);
                *word = output;
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleChain {
    text: String,
    transforms: Vec<Transform>,
}

impl RuleChain {
    pub fn parse(text: &str) -> Result<Self> {
        if text.is_empty() {
            return Err(AcxError::Attack("rule chain is empty".to_string()));
        }
        let segments: Vec<&str> = text.split('|').collect();
        if segments.len() > MAX_RULE_CHAIN_LENGTH {
            return Err(AcxError::Attack(format!(
                "rule chain has {} transforms; maximum is {MAX_RULE_CHAIN_LENGTH}",
                segments.len()
            )));
        }
        let mut transforms = Vec::with_capacity(segments.len());
        for segment in segments {
            if segment.is_empty() {
                return Err(AcxError::Attack(
                    "rule chain contains an empty transform".to_string(),
                ));
            }
            transforms.push(parse_transform(segment)?);
        }
        Ok(Self {
            text: text.to_string(),
            transforms,
        })
    }

    pub fn identity() -> Self {
        Self {
            text: "identity".to_string(),
            transforms: vec![Transform::Identity],
        }
    }

    /// Original CLI text; part of the hybrid attack signature.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Bytes a chain can add to a word (append/prepend literals only). Used by
    /// the hybrid memory estimate to bound one candidate.
    pub fn max_added_bytes(&self) -> usize {
        self.transforms
            .iter()
            .map(|transform| match transform {
                Transform::Append(literal) | Transform::Prepend(literal) => literal.len(),
                _ => 0,
            })
            .sum()
    }

    pub fn apply(&self, word: &[u8]) -> Vec<u8> {
        let mut output = word.to_vec();
        for transform in &self.transforms {
            transform.apply(&mut output);
        }
        output
    }
}

fn parse_transform(segment: &str) -> Result<Transform> {
    match segment {
        "identity" => Ok(Transform::Identity),
        "lower" => Ok(Transform::Lower),
        "upper" => Ok(Transform::Upper),
        "capitalize" => Ok(Transform::Capitalize),
        "toggle" => Ok(Transform::Toggle),
        "reverse" => Ok(Transform::Reverse),
        _ => {
            if let Some(literal) = segment.strip_prefix("append:") {
                Ok(Transform::Append(parse_literal(literal)?))
            } else if let Some(literal) = segment.strip_prefix("prepend:") {
                Ok(Transform::Prepend(parse_literal(literal)?))
            } else {
                Err(AcxError::Attack(format!(
                    "unknown rule transform `{segment}`"
                )))
            }
        }
    }
}

fn parse_literal(text: &str) -> Result<Vec<u8>> {
    if text.is_empty() {
        return Err(AcxError::Attack(
            "append/prepend requires a non-empty literal".to_string(),
        ));
    }
    let mut output = Vec::new();
    let mut chars = text.chars();
    while let Some(ch) = chars.next() {
        if ch != '?' {
            if !ch.is_ascii() || !(0x20..=0x7e).contains(&(ch as u32)) {
                return Err(AcxError::Attack(format!(
                    "rule literal {ch:?} is not printable ASCII"
                )));
            }
            output.push(ch as u8);
            continue;
        }
        match chars.next() {
            Some('?') => output.push(b'?'),
            Some(other) => return Err(AcxError::Attack(format!("unknown rule escape `?{other}`"))),
            None => {
                return Err(AcxError::Attack(
                    "rule literal ends with an unescaped `?`".to_string(),
                ))
            }
        }
    }
    if output.len() > MAX_RULE_LITERAL_BYTES {
        return Err(AcxError::Attack(format!(
            "rule literal is {} bytes; maximum is {MAX_RULE_LITERAL_BYTES}",
            output.len()
        )));
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn apply(rule: &str, word: &str) -> String {
        let chain = RuleChain::parse(rule).expect("parse rule");
        String::from_utf8_lossy(&chain.apply(word.as_bytes())).to_string()
    }

    #[test]
    fn applies_every_documented_transform() {
        assert_eq!(apply("identity", "paSS"), "paSS");
        assert_eq!(apply("lower", "paSS"), "pass");
        assert_eq!(apply("upper", "paSS"), "PASS");
        assert_eq!(apply("capitalize", "paSS"), "Pass");
        assert_eq!(apply("toggle", "paSS"), "PAss");
        assert_eq!(apply("reverse", "paSS"), "SSap");
        assert_eq!(apply("append:123", "paSS"), "paSS123");
        assert_eq!(apply("prepend:x", "paSS"), "xpaSS");
    }

    #[test]
    fn applies_chains_left_to_right() {
        assert_eq!(apply("capitalize|append:123", "paSS"), "Pass123");
        assert_eq!(apply("append:!|reverse", "ab"), "!ba");
    }

    #[test]
    fn escapes_literal_question_marks() {
        assert_eq!(apply("append:??", "a"), "a?");
        assert_eq!(apply("append:??d", "a"), "a?d");
    }

    #[test]
    fn only_ascii_case_and_reverse_touch_bytes() {
        // U+00E9 is two UTF-8 bytes; case transforms must leave both intact.
        let bytes = "aé".as_bytes();
        let lower = RuleChain::parse("lower").expect("lower").apply(bytes);
        assert_eq!(lower, bytes);
        let reverse = RuleChain::parse("reverse").expect("reverse").apply(bytes);
        assert_eq!(reverse, vec![0xA9, 0xC3, b'a']);
    }

    #[test]
    fn rejects_invalid_chains() {
        for rule in [
            "",
            "|",
            "lower|",
            "|lower",
            "lower||upper",
            "unknown",
            "append:",
            "append:é",
            "append:?x",
            "append:abc?",
            "identity|identity|identity|identity|identity|identity|identity|identity|identity",
        ] {
            assert!(RuleChain::parse(rule).is_err(), "rule {rule:?} must fail");
        }
        let long = format!("append:{}", "a".repeat(MAX_RULE_LITERAL_BYTES + 1));
        assert!(RuleChain::parse(&long).is_err());
    }

    #[test]
    fn reports_the_maximum_added_bytes() {
        assert_eq!(
            RuleChain::parse("append:123|prepend:x")
                .expect("chain")
                .max_added_bytes(),
            4
        );
        assert_eq!(
            RuleChain::parse("lower|reverse")
                .expect("chain")
                .max_added_bytes(),
            0
        );
    }

    #[test]
    fn keeps_the_original_text_for_fingerprints() {
        assert!(RuleChain::parse(" Capitalize ").is_err());
        assert_eq!(
            RuleChain::parse("capitalize|append:123")
                .expect("chain")
                .text(),
            "capitalize|append:123"
        );
        assert_eq!(RuleChain::identity().text(), "identity");
    }
}
