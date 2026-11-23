// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

//! Archive engines and the session abstraction used by the scheduler.

pub mod info;
pub mod zip;

pub use info::{ArchiveFormat, ArchiveInfo, Encryption, EntryInfo, PasswordTest};
pub use zip::{ZipFactory, ZipSession};

use crate::error::{AcxError, Result};
use std::path::Path;

/// One open archive, owned by a worker thread.
pub trait ArchiveSession: Send {
    fn info(&self) -> &ArchiveInfo;

    /// Test one candidate password. `Hit` must only be returned after the
    /// engine has verified the entry content (CRC/HMAC), not just the header.
    fn test_password(&mut self, password: &[u8]) -> Result<PasswordTest>;
}

/// Opens independent sessions for scheduler workers.
pub trait ArchiveSessionFactory: Send + Sync {
    fn open(&self) -> Result<Box<dyn ArchiveSession>>;
}

/// Detect the format by magic bytes and open a session.
pub fn open(path: &Path) -> Result<Box<dyn ArchiveSession>> {
    let mut magic = [0u8; 4];
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    file.read_exact(&mut magic)?;
    if magic == [0x50, 0x4b, 0x03, 0x04] || magic == [0x50, 0x4b, 0x05, 0x06] {
        Ok(Box::new(ZipSession::open(path)?))
    } else {
        Err(AcxError::Unsupported(format!(
            "not a ZIP archive (magic {:02x?})",
            magic
        )))
    }
}

/// Open the archive once and return its metadata.
pub fn preflight(path: &Path) -> Result<ArchiveInfo> {
    let session = open(path)?;
    Ok(session.info().clone())
}
