// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 ArchCracker contributors

//! ArchCracker core: domain, candidates, scheduling, engines, probes.
//!
//! M0 only exposes a version marker; the modules land in P1.

/// Crate version from Cargo metadata.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Human-readable product name.
pub const PRODUCT: &str = "ArchCracker";

/// Return a short version string, e.g. `ArchCracker 0.0.1`.
pub fn version_string() -> String {
    format!("{PRODUCT} {VERSION}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_not_empty() {
        assert!(!VERSION.is_empty());
        assert!(version_string().contains(PRODUCT));
    }
}
