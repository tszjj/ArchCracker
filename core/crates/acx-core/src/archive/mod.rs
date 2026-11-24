// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

//! Archive engines and the session abstraction used by the scheduler.

pub mod info;
pub mod rar;
pub mod zip;

pub use info::{ArchiveFormat, ArchiveInfo, Encryption, EntryInfo, PasswordTest};
pub use rar::{RarFactory, RarSession};
pub use zip::{ZipFactory, ZipSession};

use crate::error::{AcxError, Result};
use std::io::Read;
use std::path::Path;

/// One open archive, owned by a worker thread.
pub trait ArchiveSession: Send {
    fn info(&self) -> &ArchiveInfo;

    /// Test one candidate password. `Hit` must only be returned after the
    /// engine has verified the entry content (CRC/HMAC) or, for external RAR,
    /// after the whole archive tested successfully.
    fn test_password(&mut self, password: &[u8]) -> Result<PasswordTest>;
}

/// Opens independent sessions for scheduler workers.
pub trait ArchiveSessionFactory: Send + Sync {
    fn open(&self) -> Result<Box<dyn ArchiveSession>>;
}

/// Detect the archive format by magic bytes.
pub(crate) fn detect_format(path: &Path) -> Result<ArchiveFormat> {
    let mut file = std::fs::File::open(path)?;
    let mut magic = [0u8; 8];
    let mut filled = 0;
    while filled < magic.len() {
        match file.read(&mut magic[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) => return Err(AcxError::Io(error)),
        }
    }
    let magic = &magic[..filled];
    detect_magic(magic)
}

fn detect_magic(magic: &[u8]) -> Result<ArchiveFormat> {
    if magic.starts_with(b"PK\x03\x04") || magic.starts_with(b"PK\x05\x06") {
        Ok(ArchiveFormat::Zip)
    } else if magic.starts_with(b"Rar!\x1a\x07\x00") {
        Ok(ArchiveFormat::Rar4)
    } else if magic.starts_with(b"Rar!\x1a\x07\x01\x00") {
        Ok(ArchiveFormat::Rar5)
    } else {
        Err(AcxError::Unsupported(format!(
            "unrecognized archive magic {:02x?}",
            magic
        )))
    }
}

/// Detect the format by magic bytes and open a session.
pub fn open(path: &Path) -> Result<Box<dyn ArchiveSession>> {
    match detect_format(path)? {
        ArchiveFormat::Zip => Ok(Box::new(ZipSession::open(path)?)),
        ArchiveFormat::Rar4 | ArchiveFormat::Rar5 => Ok(Box::new(RarSession::open(path)?)),
    }
}

/// Open the archive once and return its metadata.
pub fn preflight(path: &Path) -> Result<ArchiveInfo> {
    let session = open(path)?;
    Ok(session.info().clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_zip_rar4_and_rar5_magic() {
        assert_eq!(
            detect_magic(b"PK\x03\x04").expect("zip"),
            ArchiveFormat::Zip
        );
        assert_eq!(
            detect_magic(b"Rar!\x1a\x07\x00rest").expect("rar4"),
            ArchiveFormat::Rar4
        );
        assert_eq!(
            detect_magic(b"Rar!\x1a\x07\x01\x00rest").expect("rar5"),
            ArchiveFormat::Rar5
        );
    }

    #[test]
    fn unknown_magic_is_rejected() {
        assert!(matches!(
            detect_magic(b"not an archive"),
            Err(AcxError::Unsupported(_))
        ));
        assert!(matches!(detect_magic(b""), Err(AcxError::Unsupported(_))));
    }
}
