// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

//! Archive engines and the session abstraction used by the scheduler.

pub mod info;
pub mod rar;
pub mod sevenz;
pub mod source;
pub mod zip;

pub use info::{ArchiveFormat, ArchiveInfo, Encryption, EntryInfo, PasswordTest};
pub use rar::{RarFactory, RarSession};
pub use sevenz::{SevenZFactory, SevenZSession};
pub use source::{ArchiveSource, VolumeReader};
pub use zip::{ZipFactory, ZipSession};

use crate::engines::external::CancelToken;
use crate::error::{AcxError, Result};
use std::path::Path;

/// One open archive, owned by a worker thread.
pub trait ArchiveSession: Send {
    fn info(&self) -> &ArchiveInfo;

    /// Test one candidate password. `Hit` must only be returned after the
    /// engine has verified the entry content (CRC/HMAC) or, for external RAR,
    /// after the whole archive tested successfully.
    fn test_password(&mut self, password: &[u8]) -> Result<PasswordTest>;

    /// Attach a cancellation token used by blocking external engines. Engines
    /// whose candidate test is bounded in-process may ignore it.
    fn set_cancel_token(&mut self, _token: CancelToken) {}
}

/// Opens independent sessions for scheduler workers.
pub trait ArchiveSessionFactory: Send + Sync {
    fn open(&self) -> Result<Box<dyn ArchiveSession>>;
}

/// Detect the archive format by magic bytes.
///
/// Resolves continuation parts first, so `preflight` on `movie.7z.002` sees the
/// same logical archive as `movie.7z.001`.
pub(crate) fn detect_format(path: &Path) -> Result<ArchiveFormat> {
    Ok(source::ArchiveSource::resolve(path)?.format)
}

pub(crate) fn detect_magic(magic: &[u8]) -> Result<ArchiveFormat> {
    if magic.starts_with(b"PK\x03\x04") || magic.starts_with(b"PK\x05\x06") {
        Ok(ArchiveFormat::Zip)
    } else if magic.starts_with(b"7z\xbc\xaf\x27\x1c") {
        Ok(ArchiveFormat::SevenZ)
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
        ArchiveFormat::SevenZ => Ok(Box::new(SevenZSession::open(path)?)),
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
    fn detects_zip_sevenz_rar4_and_rar5_magic() {
        assert_eq!(
            detect_magic(b"PK\x03\x04").expect("zip"),
            ArchiveFormat::Zip
        );
        assert_eq!(
            detect_magic(b"7z\xbc\xaf\x27\x1c").expect("7z"),
            ArchiveFormat::SevenZ
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
