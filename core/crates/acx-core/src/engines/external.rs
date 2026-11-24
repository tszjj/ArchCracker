// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

//! External-process boundary for user-installed engines.
//!
//! The core never embeds or links RAR code. On Windows it delegates RAR work to
//! a user-installed `UnRAR.exe`/WinRAR. This module owns process discovery,
//! stdin password transport, output capture, and timeout/kill semantics so
//! engines do not call `std::process::Command` directly.

use crate::error::{AcxError, Result};
use std::env;
use std::ffi::{OsStr, OsString};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

/// Default per-process timeout. RAR full-archive testing can be slow, but a
/// hung external engine must never hang the scheduler forever.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);

/// Maximum bytes kept from stdout/stderr; the rest is drained to avoid
/// deadlocking a child on a full pipe.
const MAX_CAPTURE_BYTES: usize = 64 * 1024;

/// Result of one external process invocation.
#[derive(Debug)]
pub struct ExternalOutput {
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub timed_out: bool,
}

/// Run `program` with `args`, optionally feeding one line to stdin.
///
/// `stdin` is written followed by `\n`, because UnRAR's password prompt is
/// line-oriented. The password therefore never appears in the process command
/// line. Output is capped, and a child that exceeds `timeout` is killed.
pub fn run<I, S>(
    program: &Path,
    args: I,
    stdin: Option<&[u8]>,
    timeout: Duration,
) -> Result<ExternalOutput>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // Do not flash a console window when a future GUI launches the engine.
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }

    let mut child = command.spawn().map_err(|error| {
        AcxError::External(format!("failed to start {}: {error}", program.display()))
    })?;

    if let Some(input) = stdin {
        if let Some(mut pipe) = child.stdin.take() {
            let mut line = Vec::with_capacity(input.len() + 1);
            line.extend_from_slice(input);
            line.push(b'\n');
            let write_result = pipe.write_all(&line);
            line.fill(0);
            // A broken pipe means the child exited before reading the prompt;
            // its exit status still provides the real verdict.
            if let Err(error) = write_result {
                if error.kind() != std::io::ErrorKind::BrokenPipe {
                    return Err(AcxError::External(format!(
                        "failed to write password to {}: {error}",
                        program.display()
                    )));
                }
            }
        }
    } else {
        // Explicitly close stdin so a prompt cannot wait forever.
        drop(child.stdin.take());
    }

    let stdout_thread = child
        .stdout
        .take()
        .map(|pipe| thread::spawn(move || read_capped(pipe)));
    let stderr_thread = child
        .stderr
        .take()
        .map(|pipe| thread::spawn(move || read_capped(pipe)));

    let deadline = Instant::now().checked_add(timeout);
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                    timed_out = true;
                    let _ = child.kill();
                    break child.wait().map_err(|error| {
                        AcxError::External(format!(
                            "failed to reap timed-out {}: {error}",
                            program.display()
                        ))
                    })?;
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => {
                return Err(AcxError::External(format!(
                    "failed to wait for {}: {error}",
                    program.display()
                )));
            }
        }
    };

    let stdout = stdout_thread
        .and_then(|handle| handle.join().ok())
        .unwrap_or_default();
    let stderr = stderr_thread
        .and_then(|handle| handle.join().ok())
        .unwrap_or_default();

    Ok(ExternalOutput {
        code: status.code(),
        stdout,
        stderr,
        timed_out,
    })
}

/// Locate a user-installed UnRAR executable.
///
/// Search order: explicit `ACX_UNRAR`, `PATH`, then the default WinRAR install
/// directories on Windows. Nothing is downloaded or bundled.
pub fn find_unrar() -> Result<PathBuf> {
    if let Some(raw) = env::var_os("ACX_UNRAR") {
        let path = PathBuf::from(raw);
        if path.is_file() {
            return Ok(path);
        }
        return Err(AcxError::External(format!(
            "ACX_UNRAR does not point to a file: {}",
            path.display()
        )));
    }

    for name in ["UnRAR.exe", "unrar.exe", "unrar"] {
        if let Some(path) = find_on_path(name) {
            return Ok(path);
        }
    }

    #[cfg(windows)]
    {
        let mut roots: Vec<OsString> = Vec::new();
        for variable in ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"] {
            if let Some(root) = env::var_os(variable) {
                roots.push(root);
            }
        }
        if let Some(local) = env::var_os("LOCALAPPDATA") {
            roots.push(local);
        }
        for root in roots {
            let root = PathBuf::from(root);
            let candidates = [
                root.join("WinRAR").join("UnRAR.exe"),
                root.join("Programs").join("WinRAR").join("UnRAR.exe"),
            ];
            for candidate in candidates {
                if candidate.is_file() {
                    return Ok(candidate);
                }
            }
        }
    }

    Err(AcxError::External(
        "UnRAR engine not found: install WinRAR/UnRAR, put UnRAR.exe on PATH, or set ACX_UNRAR"
            .to_string(),
    ))
}

/// Search one executable name on `PATH`.
fn find_on_path(name: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    for directory in env::split_paths(&path) {
        let candidate = directory.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Drain a pipe, retaining at most [`MAX_CAPTURE_BYTES`].
fn read_capped(mut reader: impl Read) -> Vec<u8> {
    let mut kept = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                let remaining = MAX_CAPTURE_BYTES.saturating_sub(kept.len());
                if remaining > 0 {
                    kept.extend_from_slice(&buffer[..read.min(remaining)]);
                }
            }
            Err(_) => break,
        }
    }
    kept
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn read_capped_keeps_only_the_prefix() {
        let input = vec![b'x'; MAX_CAPTURE_BYTES + 100];
        let output = read_capped(Cursor::new(input));
        assert_eq!(output.len(), MAX_CAPTURE_BYTES);
        assert!(output.iter().all(|byte| *byte == b'x'));
    }
}
