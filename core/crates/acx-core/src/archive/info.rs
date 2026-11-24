// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

//! Archive metadata shared by engines, scheduler, and frontends.

use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveFormat {
    Zip,
    Rar4,
    Rar5,
}

impl ArchiveFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Zip => "zip",
            Self::Rar4 => "rar4",
            Self::Rar5 => "rar5",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encryption {
    None,
    ZipCrypto,
    Aes,
    /// RAR encryption handled by the external UnRAR engine.
    Rar,
}

impl Encryption {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ZipCrypto => "zipcrypto",
            Self::Aes => "aes",
            Self::Rar => "rar",
        }
    }
}

#[derive(Debug, Clone)]
pub struct EntryInfo {
    /// Index in the archive's central directory.
    pub index: usize,
    pub name: String,
    pub uncompressed_size: u64,
    pub compressed_size: u64,
    pub encryption: Encryption,
    pub crc32: u32,
    pub is_dir: bool,
}

#[derive(Debug, Clone)]
pub struct ArchiveInfo {
    pub path: PathBuf,
    pub format: ArchiveFormat,
    pub encryption: Encryption,
    /// Smallest encrypted file selected for password testing (ZIP).
    pub selected: Option<usize>,
    /// True when the engine must test the whole archive because it cannot
    /// cheaply enumerate a verification target (external RAR full test).
    pub whole_archive: bool,
    pub entries: Vec<EntryInfo>,
}

impl ArchiveInfo {
    pub fn selected_entry(&self) -> Option<&EntryInfo> {
        self.selected.and_then(|i| self.entries.get(i))
    }

    /// Whether this archive has a target the scheduler can verify candidates
    /// against: one selected entry, or a whole-archive external test.
    pub fn has_verification_target(&self) -> bool {
        self.selected.is_some() || self.whole_archive
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordTest {
    Miss,
    Hit,
}
