// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

//! Unified fast-filter taxonomy and counters (W2-007).
//!
//! A fast filter may only reject a candidate; it never produces a hit. Each
//! filter is identified by a stable enum so reports and tests can distinguish
//! which criterion rejected how many encoding-variant attempts.

/// Criteria that can reject a candidate before full engine verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FastFilterKind {
    /// ZIP ZipCrypto check header / WinZip AES 2-byte verifier.
    ///
    /// This check is performed inside the `zip` crate before any entry is
    /// decompressed. It is cryptographically exact for wrong passwords, so it
    /// is *not* disabled by `--strict` (no new lossy criterion was added).
    ZipVerifier,
    /// 7z first-block structural probe (64 KiB prefix).
    SevenZFirstBlock,
    /// RAR5 ASCII-only password check-value comparison.
    Rar5CheckValue,
}

impl FastFilterKind {
    /// Stable report label. Keep this unchanged for log compatibility.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ZipVerifier => "zip_verifier",
            Self::SevenZFirstBlock => "sevenz_first_block",
            Self::Rar5CheckValue => "rar5_check_value",
        }
    }
}

/// Per-criterion rejection counts. Every value is an encoding-variant count.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FilterCounts {
    pub zip_verifier: u64,
    pub sevenz_first_block: u64,
    pub rar5_check_value: u64,
}

impl FilterCounts {
    /// Increment the bucket for `kind`.
    pub fn bump(&mut self, kind: FastFilterKind) {
        match kind {
            FastFilterKind::ZipVerifier => self.zip_verifier += 1,
            FastFilterKind::SevenZFirstBlock => self.sevenz_first_block += 1,
            FastFilterKind::Rar5CheckValue => self.rar5_check_value += 1,
        }
    }

    /// Sum of every criterion bucket; equals `ArchiveStats::fast_rejected`.
    pub fn total(self) -> u64 {
        self.zip_verifier + self.sevenz_first_block + self.rar5_check_value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_are_stable() {
        assert_eq!(FastFilterKind::ZipVerifier.as_str(), "zip_verifier");
        assert_eq!(
            FastFilterKind::SevenZFirstBlock.as_str(),
            "sevenz_first_block"
        );
        assert_eq!(FastFilterKind::Rar5CheckValue.as_str(), "rar5_check_value");
    }

    #[test]
    fn buckets_are_independent_and_total() {
        let mut counts = FilterCounts::default();
        counts.bump(FastFilterKind::ZipVerifier);
        counts.bump(FastFilterKind::ZipVerifier);
        counts.bump(FastFilterKind::SevenZFirstBlock);
        counts.bump(FastFilterKind::Rar5CheckValue);
        assert_eq!(counts.zip_verifier, 2);
        assert_eq!(counts.sevenz_first_block, 1);
        assert_eq!(counts.rar5_check_value, 1);
        assert_eq!(counts.total(), 4);
    }
}
