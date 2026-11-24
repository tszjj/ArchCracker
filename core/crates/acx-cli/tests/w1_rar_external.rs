// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

//! End-to-end RAR external-engine test.
//!
//! RAR fixtures are generated locally with the user-installed `Rar.exe`; the
//! test is skipped when WinRAR/UnRAR or `Rar.exe` is unavailable. No sample
//! archive is committed. CI intentionally has no RAR engine dependency.

use acx_core::engines::external::{find_unrar, run};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

const PASSWORD: &str = "P@ssw0rd123";
const HELLO: &[u8] = b"ArchCracker RAR integration fixture";

fn scratch_dir() -> &'static Path {
    static SCRATCH: OnceLock<PathBuf> = OnceLock::new();
    SCRATCH.get_or_init(|| {
        let preferred = std::env::temp_dir();
        let probe = preferred.join(format!("acx-rar-probe-{}.tmp", std::process::id()));
        let writable = std::fs::write(&probe, b"probe").is_ok();
        let _ = std::fs::remove_file(&probe);
        if writable {
            return preferred;
        }

        let mut fallback = std::env::current_exe().unwrap_or_default();
        if fallback.pop() {
            fallback.pop();
        }
        fallback.push("acx-test-tmp");
        let _ = std::fs::create_dir_all(&fallback);
        fallback
    })
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos());
        let path = scratch_dir().join(format!("acx-rar-{tag}-{}-{nanos}-{id}", std::process::id()));
        std::fs::create_dir_all(&path)
            .unwrap_or_else(|error| panic!("create {}: {error}", path.display()));
        Self { path }
    }

    fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn local_rar() -> Option<PathBuf> {
    let unrar = match find_unrar() {
        Ok(path) => path,
        Err(error) => {
            eprintln!("skipping RAR integration test: {error}");
            return None;
        }
    };
    let rar = unrar.parent()?.join("Rar.exe");
    if !rar.is_file() {
        eprintln!("skipping RAR integration test: Rar.exe not found beside UnRAR");
        return None;
    }
    Some(rar)
}

fn create_rar(rar: &Path, archive: &Path, file: &Path, password: bool) -> bool {
    let mut args: Vec<OsString> = vec!["a".into(), "-ep1".into()];
    if password {
        args.push("-p".into());
    }
    args.push(archive.as_os_str().to_os_string());
    args.push(file.as_os_str().to_os_string());

    let output = run(
        rar,
        args,
        password.then_some(PASSWORD.as_bytes()),
        std::time::Duration::from_secs(60),
    )
    .expect("run Rar.exe");
    if output.code != Some(0) {
        eprintln!(
            "Rar.exe returned {:?}: {}",
            output.code,
            String::from_utf8_lossy(&output.stderr)
        );
        return false;
    }
    true
}

fn write_dictionary(path: &Path, lines: &[&str]) {
    let mut contents = lines.join("\n");
    contents.push('\n');
    std::fs::write(path, contents)
        .unwrap_or_else(|error| panic!("create {}: {error}", path.display()));
}

#[test]
fn local_rar_external_cli() {
    let Some(rar) = local_rar() else {
        return;
    };

    let temp = TempDir::new("cli");
    let hello = temp.join("hello.txt");
    let encrypted = temp.join("encrypted.rar");
    let plain = temp.join("plain.rar");
    let hit_dict = temp.join("hit.txt");
    let miss_dict = temp.join("miss.txt");
    std::fs::write(&hello, HELLO).expect("write hello");
    write_dictionary(&hit_dict, &["wrong1", PASSWORD, "wrong2"]);
    write_dictionary(&miss_dict, &["wrong1", "wrong2"]);

    assert!(
        create_rar(&rar, &encrypted, &hello, true),
        "Rar.exe must create an encrypted fixture"
    );
    assert!(
        create_rar(&rar, &plain, &hello, false),
        "Rar.exe must create an unencrypted fixture"
    );

    let output = Command::new(env!("CARGO_BIN_EXE_acx"))
        .args(["-f"])
        .arg(&encrypted)
        .args(["-m", "dict", "-d"])
        .arg(&hit_dict)
        .args(["-t", "2"])
        .output()
        .expect("run acx");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "exit {:?}\nstdout: {stdout}\nstderr: {stderr}",
        output.status.code()
    );
    assert!(stdout.contains("Format: rar"), "stdout: {stdout}");
    assert!(stdout.contains("Encryption: rar"), "stdout: {stdout}");
    assert!(stdout.contains("FOUND:"), "stdout: {stdout}");
    assert!(stdout.contains(PASSWORD), "stdout: {stdout}");

    let output = Command::new(env!("CARGO_BIN_EXE_acx"))
        .args(["-f"])
        .arg(&encrypted)
        .args(["-d"])
        .arg(&miss_dict)
        .args(["-t", "2"])
        .output()
        .expect("run acx");
    assert_eq!(
        output.status.code(),
        Some(1),
        "wrong dictionary must exit 1\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let output = Command::new(env!("CARGO_BIN_EXE_acx"))
        .args(["-f"])
        .arg(&plain)
        .args(["-d"])
        .arg(&hit_dict)
        .output()
        .expect("run acx");
    assert_eq!(
        output.status.code(),
        Some(3),
        "unencrypted RAR must exit 3\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
