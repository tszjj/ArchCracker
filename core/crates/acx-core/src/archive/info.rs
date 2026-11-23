// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

//! Archive metadata shared by engines, scheduler, and frontends.

use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveFormat {
    Zip,
}

impl ArchiveFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Zip => "zip",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encryption {
    None,
    ZipCrypto,
    Aes,
}

impl Encryption {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::ZipCrypto => "zipcrypto",
            Self::Aes => "aes",
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
    /// Smallest encrypted file selected for password testing.
    pub selected: Option<usize>,
    pub entries: Vec<EntryInfo>,
}

impl ArchiveInfo {
    pub fn selected_entry(&self) -> Option<&EntryInfo> {
        self.selected.and_then(|i| self.entries.get(i))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordTest {
    Miss,
    Hit,
}
