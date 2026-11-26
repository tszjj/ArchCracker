// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

//! Archive metadata shared by engines, scheduler, and frontends.

use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveFormat {
    Zip,
    SevenZ,
    Rar4,
    Rar5,
}

impl ArchiveFormat {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Zip => "zip",
            Self::SevenZ => "7z",
            Self::Rar4 => "rar4",
            Self::Rar5 => "rar5",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encryption {
    None,
    ZipCrypto,
    /// WinZip AES (ZIP) or 7z AES-256.
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
    /// Engine-specific entry index (ZIP central directory or 7z file index).
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
    /// Smallest verifiable encrypted file selected for password testing.
    pub selected: Option<usize>,
    /// True when the engine must test the whole archive because it cannot
    /// cheaply enumerate a verification target (external RAR full test).
    pub whole_archive: bool,
    /// True when the archive metadata itself is encrypted (7z `-mhe=on`);
    /// entries cannot be listed until a password is known.
    pub header_encrypted: bool,
    pub entries: Vec<EntryInfo>,
}

impl ArchiveInfo {
    pub fn selected_entry(&self) -> Option<&EntryInfo> {
        self.selected.and_then(|i| self.entries.get(i))
    }

    /// Whether this archive has a target the scheduler can verify candidates
    /// against: one selected entry, a whole-archive external test, or a
    /// header-encrypted archive whose entries become available with a password.
    pub fn has_verification_target(&self) -> bool {
        self.selected.is_some() || self.whole_archive || self.header_encrypted
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordTest {
    Miss,
    Hit,
}
