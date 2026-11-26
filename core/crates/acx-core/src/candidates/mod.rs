// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

//! Candidate sources: dictionary, mask, and brute-force (W2).

pub mod dictionary;
pub mod mask;

use crate::error::Result;

pub use dictionary::{Dictionary, DictionaryStream};
pub use mask::{
    MaskEstimate, MaskSet, MaskSource, MaskSpec, MaskWarning, MAX_CUSTOM_CHARSET_BYTES,
    MAX_MASK_EXPRESSION_BYTES, MAX_MASK_POSITIONS, RECOMMENDED_MASK_POSITIONS,
};

/// One owned batch of candidates, starting at `start_index` in the source.
#[derive(Debug)]
pub struct CandidateBatch {
    pub start_index: usize,
    pub candidates: Vec<Vec<u8>>,
}

/// A bounded-memory source of password candidates.
///
/// Sources are pulled by the scheduler producer. A source may be memory-backed
/// or stream from a dictionary file; it must return candidates in file order so
/// the scheduler's candidate index remains a safe checkpoint watermark.
pub trait CandidateSource: Send {
    /// Total number of candidates in the source (known after a cheap scan for
    /// files; exact for memory sources).
    fn total(&self) -> usize;

    /// Return at most `max` candidates. `None` means end of source.
    fn next_batch(&mut self, max: usize) -> Result<Option<CandidateBatch>>;
}
