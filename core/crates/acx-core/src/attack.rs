// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

//! Attack parameters shared by the CLI and the scheduler.

use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttackMode {
    Dictionary,
}

#[derive(Debug, Clone)]
pub struct AttackSpec {
    pub mode: AttackMode,
    pub dictionary: PathBuf,
    pub threads: usize,
}

impl AttackSpec {
    pub fn new(dictionary: PathBuf, threads: usize) -> Self {
        Self {
            mode: AttackMode::Dictionary,
            dictionary,
            threads: threads.max(1),
        }
    }
}
