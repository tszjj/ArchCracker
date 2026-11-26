// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

//! End-to-end test of the W1 7z + dictionary CLI path.
//!
//! Fixtures are generated in-process with the `sevenz-rust2` writer; no binary
//! archive is committed. The writer output is also checked against the official
//! 7-Zip CLI manually (documented in `docs/tasks/W1-004-sevenz.md`).

use sevenz_rust2::encoder_options::AesEncoderOptions;
use sevenz_rust2::{ArchiveEntry, ArchiveWriter, EncoderConfiguration, EncoderMethod, Password};
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

const PASSWORD: &str = "P@ssw0rd123";
const HELLO: &[u8] = b"ArchCracker W1 7z integration fixture";

fn scratch_dir() -> &'static Path {
    static SCRATCH: OnceLock<PathBuf> = OnceLock::new();
    SCRATCH.get_or_init(|| {
        let preferred = std::env::temp_dir();
        let probe = preferred.join(format!("acx-cli-7z-probe-{}.tmp", std::process::id()));
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
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or(0);
        let path = scratch_dir().join(format!(
            "acx-cli-7z-{tag}-{}-{nanos}-{id}",
            std::process::id()
        ));
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

/// Write a 7z fixture. `encrypted` adds AES-256 after LZMA2; `header_encrypted`
/// also encrypts the metadata (`-mhe=on` in 7-Zip terms).
fn write_7z(path: &Path, encrypted: bool, header_encrypted: bool, stored: bool, contents: &[u8]) {
    let mut writer = ArchiveWriter::create(path).expect("create 7z");
    writer.set_encrypt_header(header_encrypted);
    let mut methods = vec![EncoderConfiguration::new(if stored {
        EncoderMethod::COPY
    } else {
        EncoderMethod::LZMA2
    })];
    if encrypted {
        methods.push(AesEncoderOptions::new(Password::from(PASSWORD)).into());
    }
    writer.set_content_methods(methods);
    writer
        .push_archive_entry(
            ArchiveEntry::new_file("hello.txt"),
            Some(Cursor::new(contents.to_vec())),
        )
        .expect("push hello.txt");
    writer.finish().expect("finish 7z");
}

fn write_dictionary(path: &Path, lines: &[&str]) {
    let mut contents = lines.join("\n");
    contents.push('\n');
    std::fs::write(path, contents)
        .unwrap_or_else(|error| panic!("create {}: {error}", path.display()));
}

fn acx() -> Command {
    Command::new(env!("CARGO_BIN_EXE_acx"))
}

#[test]
fn dictionary_attack_finds_7z_aes_password() {
    let temp = TempDir::new("aes-hit");
    let archive = temp.join("encrypted.7z");
    let dict = temp.join("dictionary.txt");
    write_7z(&archive, true, false, false, HELLO);
    write_dictionary(&dict, &["wrong1", PASSWORD, "wrong2"]);

    let output = acx()
        .arg("-f")
        .arg(&archive)
        .arg("-m")
        .arg("dict")
        .arg("-d")
        .arg(&dict)
        .arg("-t")
        .arg("4")
        .output()
        .expect("run acx");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "exit {:?}\nstdout: {stdout}\nstderr: {stderr}",
        output.status.code()
    );
    assert!(stdout.contains("FOUND:"), "stdout: {stdout}");
    assert!(stdout.contains(PASSWORD), "stdout: {stdout}");
    assert!(stdout.contains("Format: 7z"), "stdout: {stdout}");
    assert!(stdout.contains("Encryption: aes"), "stdout: {stdout}");
}

#[test]
fn dictionary_attack_finds_7z_header_encrypted_password() {
    let temp = TempDir::new("header-hit");
    let archive = temp.join("header.7z");
    let dict = temp.join("dictionary.txt");
    write_7z(&archive, true, true, false, HELLO);
    write_dictionary(&dict, &["wrong1", PASSWORD]);

    let output = acx()
        .arg("-f")
        .arg(&archive)
        .arg("-m")
        .arg("dict")
        .arg("-d")
        .arg(&dict)
        .arg("-t")
        .arg("2")
        .output()
        .expect("run acx");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "exit {:?}\nstdout: {stdout}\nstderr: {stderr}",
        output.status.code()
    );
    assert!(stdout.contains("FOUND:"), "stdout: {stdout}");
    assert!(
        stdout.contains("Entries: n/a (encrypted header)"),
        "stdout: {stdout}"
    );
    assert!(stdout.contains(PASSWORD), "stdout: {stdout}");
}

#[test]
fn wrong_7z_dictionary_exits_one() {
    let temp = TempDir::new("miss");
    let archive = temp.join("encrypted.7z");
    let dict = temp.join("dictionary.txt");
    write_7z(&archive, true, false, false, HELLO);
    write_dictionary(&dict, &["wrong1", "wrong2", "wrong3"]);

    let output = acx()
        .arg("-f")
        .arg(&archive)
        .arg("-d")
        .arg(&dict)
        .arg("-t")
        .arg("3")
        .output()
        .expect("run acx");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(1),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(stdout.contains("NOT FOUND"), "stdout: {stdout}");
}

#[test]
fn stored_7z_wrong_dictionary_exits_one() {
    // Stored AES entries cannot be rejected by the first-block probe; the full
    // CRC check must still turn these candidates into misses, not errors.
    let temp = TempDir::new("stored-miss");
    let archive = temp.join("stored.7z");
    let dict = temp.join("dictionary.txt");
    write_7z(&archive, true, false, true, HELLO);
    write_dictionary(&dict, &["wrong1", "wrong2"]);

    let output = acx()
        .arg("-f")
        .arg(&archive)
        .arg("-d")
        .arg(&dict)
        .arg("-t")
        .arg("2")
        .output()
        .expect("run acx");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(1),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(stdout.contains("NOT FOUND"), "stdout: {stdout}");
}

#[test]
fn unencrypted_7z_exits_three() {
    let temp = TempDir::new("plain");
    let archive = temp.join("plain.7z");
    let dict = temp.join("dictionary.txt");
    write_7z(&archive, false, false, false, HELLO);
    write_dictionary(&dict, &[PASSWORD]);

    let output = acx()
        .arg("-f")
        .arg(&archive)
        .arg("-d")
        .arg(&dict)
        .output()
        .expect("run acx");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(3),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stderr.contains("not encrypted") || stderr.contains("no file entries"),
        "stderr: {stderr}"
    );
}

/// Optional differential check against the official 7-Zip CLI.
///
/// CI does not ship 7-Zip, so this is ignored by default. Run explicitly:
///
/// ```text
/// set ACX_7Z=C:\path\to\7z.exe
/// cargo test -p acx-cli --test w1_sevenz -- --ignored
/// ```
#[test]
#[ignore = "requires ACX_7Z pointing at the official 7-Zip CLI"]
fn official_7zip_cli_differential() {
    let exe = std::env::var_os("ACX_7Z")
        .map(PathBuf::from)
        .expect("set ACX_7Z to the official 7z/7zr executable");
    let temp = TempDir::new("official");
    let input = temp.join("hello.txt");
    std::fs::write(&input, HELLO).expect("write input");
    let dict = temp.join("dictionary.txt");
    write_dictionary(&dict, &["wrong1", PASSWORD]);

    let cases = [
        ("file.7z", &["-pP@ssw0rd123", "-mhe=off"][..]),
        ("header.7z", &["-pP@ssw0rd123", "-mhe=on"][..]),
        ("stored.7z", &["-pP@ssw0rd123", "-mx=0"][..]),
        ("solid.7z", &["-pP@ssw0rd123", "-ms=on"][..]),
    ];
    for (name, switches) in cases {
        let archive = temp.join(name);
        let mut command = Command::new(&exe);
        command.arg("a").arg("-t7z").args(switches);
        command.arg(&archive).arg(&input);
        let creation = command.output().expect("run official 7-Zip");
        assert!(
            creation.status.success(),
            "7-Zip could not create {name}: {}",
            String::from_utf8_lossy(&creation.stderr)
        );

        let output = acx()
            .arg("-f")
            .arg(&archive)
            .arg("-d")
            .arg(&dict)
            .arg("-t")
            .arg("2")
            .output()
            .expect("run acx");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "{name}: exit {:?}\nstdout: {stdout}\nstderr: {stderr}",
            output.status.code()
        );
        assert!(stdout.contains("FOUND:"), "{name}: {stdout}");
    }

    // A plain archive created by 7-Zip must stay a non-target.
    let plain = temp.join("plain.7z");
    let creation = Command::new(&exe)
        .arg("a")
        .arg("-t7z")
        .arg(&plain)
        .arg(&input)
        .output()
        .expect("run official 7-Zip");
    assert!(
        creation.status.success(),
        "7-Zip could not create plain.7z: {}",
        String::from_utf8_lossy(&creation.stderr)
    );
    let output = acx()
        .arg("-f")
        .arg(&plain)
        .arg("-d")
        .arg(&dict)
        .output()
        .expect("run acx");
    assert_eq!(output.status.code(), Some(3));
}
