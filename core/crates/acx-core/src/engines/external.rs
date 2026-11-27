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
use std::ffi::OsStr;
#[cfg(windows)]
use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
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
    pub cancelled: bool,
}

/// Cooperative cancellation flag shared with long-running external engines.
#[derive(Debug, Clone, Default)]
pub struct CancelToken {
    flag: Arc<AtomicBool>,
}

impl CancelToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }
}

/// Maximum bytes accepted for one stdin password line. RAR passwords are far
/// smaller; this prevents a pathological candidate from blocking on a full
/// pipe before the timeout loop starts.
const MAX_STDIN_BYTES: usize = 4096;

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
    run_cancellable(program, args, stdin, timeout, None)
}

/// Same as [`run`], but aborts the child when `cancel` is set.
pub fn run_cancellable<I, S>(
    program: &Path,
    args: I,
    stdin: Option<&[u8]>,
    timeout: Duration,
    cancel: Option<&CancelToken>,
) -> Result<ExternalOutput>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    if cancel.is_some_and(CancelToken::is_cancelled) {
        return Ok(ExternalOutput {
            code: None,
            stdout: Vec::new(),
            stderr: Vec::new(),
            timed_out: false,
            cancelled: true,
        });
    }
    if stdin.is_some_and(|input| input.len() > MAX_STDIN_BYTES) {
        return Err(AcxError::Unsupported(format!(
            "stdin password exceeds the {MAX_STDIN_BYTES}-byte external-engine limit"
        )));
    }

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

    let stdout_thread = child
        .stdout
        .take()
        .map(|pipe| thread::spawn(move || read_capped(pipe)));
    let stderr_thread = child
        .stderr
        .take()
        .map(|pipe| thread::spawn(move || read_capped(pipe)));

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
                    let _ = child.kill();
                    let _ = child.wait();
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

    let deadline = Instant::now().checked_add(timeout);
    let mut timed_out = false;
    let mut cancelled = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if cancel.is_some_and(CancelToken::is_cancelled) {
                    cancelled = true;
                    let _ = child.kill();
                    break child.wait().map_err(|error| {
                        AcxError::External(format!(
                            "failed to reap cancelled {}: {error}",
                            program.display()
                        ))
                    })?;
                }
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
                let _ = child.kill();
                let _ = child.wait();
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
        cancelled,
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

/// Encode a UTF-8 candidate for a console-oriented external engine.
///
/// UnRAR reads a redirected password prompt using the Windows OEM code page,
/// not UTF-8. Feeding raw UTF-8 silently turns a correct non-ASCII password
/// into a miss. On other platforms the bytes are passed through unchanged.
#[cfg(windows)]
pub fn encode_password(input: &[u8]) -> Result<std::borrow::Cow<'_, [u8]>> {
    use std::borrow::Cow;
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Globalization::{GetOEMCP, WideCharToMultiByte, WC_NO_BEST_FIT_CHARS};

    let Ok(text) = std::str::from_utf8(input) else {
        // A caller may pass an already-OEM/raw byte variant; forward it
        // unchanged instead of failing the whole attack.
        return Ok(Cow::Borrowed(input));
    };
    // SAFETY: `GetOEMCP` has no preconditions and returns the process OEM code
    // page without dereferencing any caller-provided pointer.
    let code_page = unsafe { GetOEMCP() };
    if code_page == 65001 {
        return Ok(Cow::Borrowed(input));
    }

    let wide: Vec<u16> = text.encode_utf16().collect();
    if wide.is_empty() {
        return Ok(Cow::Owned(Vec::new()));
    }
    let wide_len = i32::try_from(wide.len()).map_err(|_| {
        AcxError::Unsupported("RAR password is too long for the external engine".to_string())
    })?;

    let mut used_default = 0i32;
    // SAFETY: `wide` is a valid UTF-16 slice of `wide_len` elements, the output
    // pointer is null with capacity 0 (size query), and `used_default` is a
    // valid writable BOOL.
    let needed = unsafe {
        WideCharToMultiByte(
            code_page,
            WC_NO_BEST_FIT_CHARS,
            wide.as_ptr(),
            wide_len,
            null_mut(),
            0,
            null(),
            &mut used_default,
        )
    };
    if needed <= 0 {
        return Err(AcxError::External(format!(
            "failed to encode RAR password for OEM code page {code_page}"
        )));
    }

    let mut output = vec![0u8; needed as usize];
    // SAFETY: `output` has exactly `needed` writable bytes as returned by the
    // size query; the input slice and `used_default` pointers are valid.
    let written = unsafe {
        WideCharToMultiByte(
            code_page,
            WC_NO_BEST_FIT_CHARS,
            wide.as_ptr(),
            wide_len,
            output.as_mut_ptr(),
            needed,
            null(),
            &mut used_default,
        )
    };
    if written != needed || used_default != 0 {
        return Err(AcxError::Unsupported(format!(
            "RAR password contains characters not representable in OEM code page {code_page}"
        )));
    }
    Ok(Cow::Owned(output))
}

/// On non-Windows platforms, pass candidate bytes through unchanged.
#[cfg(not(windows))]
pub fn encode_password(input: &[u8]) -> Result<std::borrow::Cow<'_, [u8]>> {
    Ok(std::borrow::Cow::Borrowed(input))
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

    #[test]
    fn ascii_password_is_unchanged_by_console_encoding() {
        assert_eq!(
            encode_password(b"P@ssw0rd").expect("ASCII").as_ref(),
            b"P@ssw0rd"
        );
    }

    #[test]
    fn raw_non_utf8_password_passes_through() {
        assert_eq!(
            encode_password(&[0x82]).expect("raw bytes").as_ref(),
            &[0x82]
        );
    }

    #[cfg(windows)]
    #[test]
    fn cancel_kills_a_running_child() {
        let token = CancelToken::new();
        let canceller = token.clone();
        let handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            canceller.cancel();
        });
        let started = Instant::now();
        let output = run_cancellable(
            Path::new("powershell.exe"),
            ["-NoProfile", "-Command", "Start-Sleep -Seconds 10"],
            None,
            Duration::from_secs(10),
            Some(&token),
        )
        .expect("start powershell");
        handle.join().expect("canceller");
        assert!(output.cancelled);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[cfg(unix)]
    #[test]
    fn cancel_kills_a_running_child() {
        let token = CancelToken::new();
        let canceller = token.clone();
        let handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            canceller.cancel();
        });
        let started = Instant::now();
        let output = run_cancellable(
            Path::new("sh"),
            ["-c", "exec sleep 10"],
            None,
            Duration::from_secs(10),
            Some(&token),
        )
        .expect("start sh");
        handle.join().expect("canceller");
        assert!(output.cancelled);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[cfg(windows)]
    #[test]
    fn timeout_kills_a_stuck_child() {
        let output = run(
            Path::new("powershell.exe"),
            ["-NoProfile", "-Command", "Start-Sleep -Seconds 5"],
            None,
            Duration::from_millis(100),
        )
        .expect("start powershell");
        assert!(output.timed_out);
    }

    #[cfg(unix)]
    #[test]
    fn timeout_kills_a_stuck_child() {
        let output = run(
            Path::new("sh"),
            ["-c", "exec sleep 5"],
            None,
            Duration::from_millis(100),
        )
        .expect("start sh");
        assert!(output.timed_out);
    }
}
