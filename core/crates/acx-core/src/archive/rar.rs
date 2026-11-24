// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

//! RAR engine backed by a user-installed `UnRAR.exe`.
//!
//! This is deliberately a whole-archive test: the UnRAR command line has no
//! multi-password session, and its listing output is localized, so parsing a
//! "smallest entry" is not reliable. W1-003 accepts the extra cost to keep the
//! correctness and licensing boundary simple. Clean-room header/KDF probes can
//! later reject most candidates before this process runs.

use super::info::{ArchiveFormat, ArchiveInfo, Encryption, PasswordTest};
use super::{ArchiveSession, ArchiveSessionFactory};
use crate::engines::external::{self, ExternalOutput, DEFAULT_TIMEOUT};
use crate::error::{AcxError, Result};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// One RAR session, owned by a scheduler worker.
pub struct RarSession {
    path: PathBuf,
    engine: PathBuf,
    info: ArchiveInfo,
    timeout: Duration,
}

impl RarSession {
    /// Open a RAR archive using a discovered user-installed engine.
    pub fn open(path: &Path) -> Result<Self> {
        let format = super::detect_format(path)?;
        let engine = external::find_unrar()?;
        Self::open_with_engine(path, format, engine)
    }

    /// Open with an explicit engine path (used by tests and diagnostics).
    pub fn open_with_engine(path: &Path, format: ArchiveFormat, engine: PathBuf) -> Result<Self> {
        if !matches!(format, ArchiveFormat::Rar4 | ArchiveFormat::Rar5) {
            return Err(AcxError::Unsupported(format!(
                "not a RAR archive (format {})",
                format.as_str()
            )));
        }

        let info = preflight(path, format, &engine)?;
        Ok(Self {
            path: path.to_path_buf(),
            engine,
            info,
            timeout: DEFAULT_TIMEOUT,
        })
    }

    /// Override the per-process timeout (useful for large local fixtures).
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

impl ArchiveSession for RarSession {
    fn info(&self) -> &ArchiveInfo {
        &self.info
    }

    fn test_password(&mut self, password: &[u8]) -> Result<PasswordTest> {
        if !self.info.whole_archive {
            return Err(AcxError::NotEncrypted);
        }

        // UnRAR's password prompt is line-oriented. A newline cannot be
        // represented through stdin; report it as a miss rather than silently
        // testing a truncated password.
        if password_has_line_break(password) {
            return Ok(PasswordTest::Miss);
        }

        let output = external::run(
            &self.engine,
            test_args(&self.path),
            Some(password),
            self.timeout,
        )?;
        if output.timed_out {
            return Err(AcxError::External(format!(
                "UnRAR timed out after {:?} while testing a candidate",
                self.timeout
            )));
        }

        match output.code {
            Some(0) => Ok(PasswordTest::Hit),
            Some(11) => Ok(PasswordTest::Miss),
            _ => Err(engine_failure("test", &output)),
        }
    }
}

/// Opens a fresh [`RarSession`] per scheduler worker.
pub struct RarFactory {
    pub path: PathBuf,
    engine: PathBuf,
}

impl RarFactory {
    /// Discover the user-installed engine once, then reuse it for every worker.
    pub fn new(path: PathBuf) -> Result<Self> {
        let engine = external::find_unrar()?;
        Ok(Self { path, engine })
    }

    /// Explicit engine path for tests and diagnostics.
    pub fn with_engine(path: PathBuf, engine: PathBuf) -> Self {
        Self { path, engine }
    }
}

impl ArchiveSessionFactory for RarFactory {
    fn open(&self) -> Result<Box<dyn ArchiveSession>> {
        let format = super::detect_format(&self.path)?;
        Ok(Box::new(RarSession::open_with_engine(
            &self.path,
            format,
            self.engine.clone(),
        )?))
    }
}

/// Probe exit codes and determine whether the archive is encrypted.
fn preflight(path: &Path, format: ArchiveFormat, engine: &Path) -> Result<ArchiveInfo> {
    let test = external::run(engine, preflight_args(path), None, DEFAULT_TIMEOUT)?;
    if test.timed_out {
        return Err(AcxError::External(format!(
            "UnRAR preflight timed out after {:?}",
            DEFAULT_TIMEOUT
        )));
    }

    match test.code {
        Some(0) => Ok(ArchiveInfo {
            path: path.to_path_buf(),
            format,
            encryption: Encryption::None,
            selected: None,
            whole_archive: false,
            entries: Vec::new(),
        }),
        Some(11) => {
            // Encrypted. `l -p-` succeeds for file-encrypted headers and fails
            // for header-encrypted archives; both are tested the same way, but
            // the distinction is useful in diagnostics.
            let listing = external::run(engine, listing_args(path), None, DEFAULT_TIMEOUT)?;
            if listing.timed_out {
                return Err(AcxError::External(format!(
                    "UnRAR listing timed out after {:?}",
                    DEFAULT_TIMEOUT
                )));
            }
            match listing.code {
                Some(0) | Some(11) => Ok(ArchiveInfo {
                    path: path.to_path_buf(),
                    format,
                    encryption: Encryption::Rar,
                    selected: None,
                    whole_archive: true,
                    entries: Vec::new(),
                }),
                _ => Err(engine_failure("listing", &listing)),
            }
        }
        _ => Err(engine_failure("preflight", &test)),
    }
}

fn preflight_args(path: &Path) -> Vec<OsString> {
    vec![
        "t".into(),
        "-cfg-".into(),
        "-c-".into(),
        "-idq".into(),
        "-p-".into(),
        path.as_os_str().to_os_string(),
    ]
}

fn listing_args(path: &Path) -> Vec<OsString> {
    vec![
        "l".into(),
        "-cfg-".into(),
        "-c-".into(),
        "-idq".into(),
        "-p-".into(),
        path.as_os_str().to_os_string(),
    ]
}

fn test_args(path: &Path) -> Vec<OsString> {
    vec![
        "t".into(),
        "-cfg-".into(),
        "-c-".into(),
        "-idq".into(),
        "-p".into(),
        path.as_os_str().to_os_string(),
    ]
}

fn password_has_line_break(password: &[u8]) -> bool {
    password.iter().any(|byte| *byte == b'\n' || *byte == b'\r')
}

/// Normalize an unexpected external exit into an actionable error.
fn engine_failure(action: &str, output: &ExternalOutput) -> AcxError {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let detail = stderr.trim();
    let detail = if detail.is_empty() {
        String::new()
    } else {
        format!(": {detail}")
    };
    AcxError::External(format!(
        "UnRAR {action} failed with exit code {}{detail}",
        output
            .code
            .map_or_else(|| "unknown".to_string(), |code| code.to_string())
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preflight_arguments_never_contain_a_password() {
        let args = preflight_args(Path::new("archive.rar"));
        assert!(args
            .iter()
            .all(|arg| !arg.to_string_lossy().contains("P@ss")));
        assert!(args.iter().any(|arg| arg == "-p-"));
    }

    #[test]
    fn test_arguments_prompt_instead_of_embedding_password() {
        let args = test_args(Path::new("archive.rar"));
        assert!(args.iter().any(|arg| arg == "-p"));
        assert!(args
            .iter()
            .all(|arg| !arg.to_string_lossy().contains("P@ss")));
    }

    #[test]
    fn newline_password_is_detected() {
        assert!(password_has_line_break(b"abc\ndef"));
        assert!(password_has_line_break(b"abc\rdef"));
        assert!(!password_has_line_break(b"normal"));
    }

    #[test]
    fn missing_engine_is_an_external_error() {
        let error = match RarSession::open_with_engine(
            Path::new("missing.rar"),
            ArchiveFormat::Rar5,
            PathBuf::from("definitely-not-an-unrar-binary"),
        ) {
            Ok(_) => panic!("missing engine must fail"),
            Err(error) => error,
        };
        assert!(matches!(error, AcxError::External(_)));
    }
}
