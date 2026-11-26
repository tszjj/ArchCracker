// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

//! ArchCracker core: archive preflight, ZIP sessions, dictionary candidates,
//! and the multi-threaded password scheduler.

pub mod archive;
pub mod attack;
pub mod candidates;
pub mod checkpoint;
pub mod engines;
pub mod error;
pub mod estimate;
pub mod scheduler;

pub use error::{AcxError, Result};

/// Crate version from Cargo metadata.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Human-readable product name.
pub const PRODUCT: &str = "ArchCracker";

/// Return a short version string, e.g. `ArchCracker 0.1.0`.
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
