// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

//! Engine boundaries.
//!
//! `external` owns user-installed process engines (currently UnRAR). Keeping
//! this separate from archive parsing makes the licensing boundary auditable.

pub mod external;

pub use external::{encode_password, find_unrar, run, ExternalOutput, DEFAULT_TIMEOUT};
