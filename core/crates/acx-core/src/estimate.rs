// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

//! Shared memory estimate for the mask, brute, and hybrid candidate sources.
//!
//! The scheduler keeps a compact completion bitmap with one bit per candidate
//! (`ceil(total / 8)` bytes) and may hold `threads + 3` candidate batches at
//! once (one per worker, two queued, one pending in the producer). This module
//! turns those scheduler facts plus a mode-specific candidate size bound into a
//! single estimate, so every attack mode prints the same numbers.
//!
//! The estimate covers the **core-side heap only**: the completion bitmap,
//! candidate batches, and source-owned buffers. Archive sessions (ZIP central
//! directory, 7z metadata, external UnRAR processes) are not included and must
//! be labelled separately by callers.

use crate::scheduler::{batch_candidates, MAX_THREADS};
use std::mem::size_of;

/// Warn when the completion bitmap alone reaches 128 MB (decimal).
pub const WATERMARK_WARNING_BYTES: u128 = 128_000_000;

/// Rounded allocation size for one candidate payload, including allocator
/// bookkeeping. The exact allocator class is platform-specific; a 16-byte
/// granularity plus a 16-byte header is a conservative small-allocation bound.
const ALLOCATION_GRANULARITY: u128 = 16;
const ALLOCATION_HEADER: u128 = 16;

/// Inputs for [`estimate_space`]. Every mode fills the same fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpaceInput {
    /// Candidates in the attack, as `u128` so over-`usize` estimates still work.
    pub total: u128,
    /// Worker threads the attack will use (clamped by the scheduler).
    pub threads: usize,
    /// Upper bound for one candidate payload in bytes. Uses the mode's maximum
    /// (longest mask, `max-len`, longest dictionary line), not an average.
    pub max_candidate_bytes: u128,
    /// Hard per-batch byte cap enforced by the source, if any (dictionary and
    /// hybrid use 8 MiB; mask/brute candidates are small enough to skip it).
    pub batch_bytes_cap: Option<u128>,
    /// Source-owned buffers that live for the whole run (charset tables,
    /// dictionary read buffer, one held line).
    pub source_bytes: u128,
}

/// Per-mode memory estimate shown before an attack starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpaceEstimate {
    /// Candidates in the attack (echoed from the input for display).
    pub total: u128,
    /// Completion bitmap: `ceil(total / 8)` bytes, allocated eagerly.
    pub watermark_bytes: u128,
    /// Candidates the scheduler asks for in one batch.
    pub candidates_per_batch: u128,
    /// Batches that may be resident at once (`threads + 3`).
    pub in_flight_batches: u128,
    /// Estimated bytes for all in-flight batches.
    pub in_flight_bytes: u128,
    /// Source-owned buffers passed through from [`SpaceInput`].
    pub source_bytes: u128,
    /// `watermark_bytes + in_flight_bytes + source_bytes`.
    pub estimated_peak_bytes: u128,
    pub warnings: Vec<SpaceWarning>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpaceWarning {
    Watermark { bytes: u128, threshold: u128 },
}

impl std::fmt::Display for SpaceWarning {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Watermark { bytes, threshold } => write!(
                formatter,
                "completion bitmap is {:.1} MB, above the {} MB warning threshold; reduce the keyspace or length range",
                *bytes as f64 / 1_000_000.0,
                threshold / 1_000_000
            ),
        }
    }
}

/// Estimate core-side memory for one attack.
pub fn estimate_space(input: &SpaceInput) -> SpaceEstimate {
    let threads = input.threads.clamp(1, MAX_THREADS);
    let candidates_per_batch = batch_candidates(threads) as u128;
    let payload = round_up(
        input.max_candidate_bytes.saturating_add(ALLOCATION_HEADER),
        ALLOCATION_GRANULARITY,
    );
    let per_candidate = size_of::<Vec<u8>>() as u128 + payload;
    let mut batch_bytes = candidates_per_batch.saturating_mul(per_candidate);
    if let Some(cap) = input.batch_bytes_cap {
        batch_bytes = batch_bytes.min(cap);
    }
    let in_flight_batches = threads as u128 + 3;
    let in_flight_bytes = batch_bytes.saturating_mul(in_flight_batches);
    let watermark_bytes = input.total.div_ceil(8);
    let estimated_peak_bytes = watermark_bytes
        .saturating_add(in_flight_bytes)
        .saturating_add(input.source_bytes);

    let mut warnings = Vec::new();
    if watermark_bytes > WATERMARK_WARNING_BYTES {
        warnings.push(SpaceWarning::Watermark {
            bytes: watermark_bytes,
            threshold: WATERMARK_WARNING_BYTES,
        });
    }

    SpaceEstimate {
        total: input.total,
        watermark_bytes,
        candidates_per_batch,
        in_flight_batches,
        in_flight_bytes,
        source_bytes: input.source_bytes,
        estimated_peak_bytes,
        warnings,
    }
}

fn round_up(value: u128, granularity: u128) -> u128 {
    value.div_ceil(granularity).saturating_mul(granularity)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(total: u128, threads: usize, max_candidate_bytes: u128) -> SpaceInput {
        SpaceInput {
            total,
            threads,
            max_candidate_bytes,
            batch_bytes_cap: None,
            source_bytes: 4096,
        }
    }

    #[test]
    fn watermark_is_one_bit_per_candidate() {
        assert_eq!(estimate_space(&input(0, 1, 8)).watermark_bytes, 0);
        assert_eq!(estimate_space(&input(1, 1, 8)).watermark_bytes, 1);
        assert_eq!(estimate_space(&input(64, 1, 8)).watermark_bytes, 8);
        assert_eq!(estimate_space(&input(65, 1, 8)).watermark_bytes, 9);
        assert_eq!(
            estimate_space(&input(1_000_000, 1, 8)).watermark_bytes,
            125_000
        );
    }

    #[test]
    fn batch_shape_matches_the_scheduler() {
        let one = estimate_space(&input(1_000_000, 1, 8));
        assert_eq!(one.candidates_per_batch, 1024);
        assert_eq!(one.in_flight_batches, 4);

        let fourteen = estimate_space(&input(1_000_000, 14, 8));
        assert_eq!(fourteen.candidates_per_batch, 240);
        assert_eq!(fourteen.in_flight_batches, 17);

        let clamped = estimate_space(&input(1_000_000, 1000, 8));
        assert_eq!(clamped.candidates_per_batch, 15);
        assert_eq!(clamped.in_flight_batches, 259);
    }

    #[test]
    fn batch_cap_limits_in_flight_bytes() {
        let mut with_cap = input(1_000_000, 14, 1024 * 1024);
        with_cap.batch_bytes_cap = Some(8 * 1024 * 1024);
        let estimate = estimate_space(&with_cap);
        assert_eq!(estimate.in_flight_bytes, 17 * 8 * 1024 * 1024);

        let uncapped = estimate_space(&input(1_000_000, 14, 128));
        assert!(uncapped.in_flight_bytes < 1024 * 1024);
    }

    #[test]
    fn warns_above_the_watermark_threshold() {
        let below = estimate_space(&input(WATERMARK_WARNING_BYTES * 8, 1, 8));
        assert!(below.warnings.is_empty());

        let above = estimate_space(&input(WATERMARK_WARNING_BYTES * 8 + 1, 1, 8));
        assert_eq!(above.warnings.len(), 1);
        assert!(matches!(above.warnings[0], SpaceWarning::Watermark { .. }));
    }

    #[test]
    fn peak_sums_the_three_components() {
        let estimate = estimate_space(&input(80, 2, 16));
        assert_eq!(
            estimate.estimated_peak_bytes,
            estimate.watermark_bytes + estimate.in_flight_bytes + estimate.source_bytes
        );
    }
}
