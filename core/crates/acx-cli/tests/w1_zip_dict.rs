// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

//! End-to-end test of the W1 ZIP + dictionary CLI path.
//!
//! Fixtures (an encrypted ZIP, an unencrypted ZIP, and dictionaries) are
//! generated at test time; no binary archive is committed to the repository.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use zip::unstable::write::FileOptionsExt;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

const PASSWORD: &str = "P@ssw0rd123";
const HELLO: &[u8] = b"ArchCracker W1 integration fixture";

/// Directory for generated fixtures, preferring the OS temp directory.
///
/// Some confined test harnesses deny child processes writes under `%TEMP%`
/// even when the launching shell can write there, so probe first and fall
/// back to a scratch directory inside the build's `target/` tree.
fn scratch_dir() -> &'static Path {
    static SCRATCH: OnceLock<PathBuf> = OnceLock::new();
    SCRATCH.get_or_init(|| {
        let preferred = std::env::temp_dir();
        let probe = preferred.join(format!("acx-cli-w1-probe-{}.tmp", std::process::id()));
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

/// Process-unique scratch directory removed (best effort) on drop.
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
            "acx-cli-w1-{tag}-{}-{nanos}-{id}",
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

/// Write a ZipCrypto (legacy) ZIP with one stored `hello.txt` entry.
fn write_zipcrypto_zip(path: &Path) {
    let file = std::fs::File::create(path)
        .unwrap_or_else(|error| panic!("create {}: {error}", path.display()));
    let mut writer = ZipWriter::new(file);

    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .with_deprecated_encryption(PASSWORD.as_bytes())
        .expect("ZipCrypto file options");
    writer
        .start_file("hello.txt", options)
        .expect("start hello.txt");
    writer.write_all(HELLO).expect("write hello.txt");
    writer.finish().expect("finish encrypted zip");
}

/// Write a WinZip AES-256 ZIP with one stored `hello.txt` entry.
fn write_aes_zip(path: &Path) {
    let file = std::fs::File::create(path)
        .unwrap_or_else(|error| panic!("create {}: {error}", path.display()));
    let mut writer = ZipWriter::new(file);

    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .with_aes_encryption(zip::AesMode::Aes256, PASSWORD);
    writer
        .start_file("hello.txt", options)
        .expect("start AES hello.txt");
    writer.write_all(HELLO).expect("write AES hello.txt");
    writer.finish().expect("finish AES zip");
}

/// Write an unencrypted, stored ZIP with one `hello.txt` entry.
fn write_plain_zip(path: &Path) {
    let file = std::fs::File::create(path)
        .unwrap_or_else(|error| panic!("create {}: {error}", path.display()));
    let mut writer = ZipWriter::new(file);

    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    writer
        .start_file("hello.txt", options)
        .expect("start hello.txt");
    writer.write_all(HELLO).expect("write hello.txt");
    writer.finish().expect("finish plain zip");
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
fn dictionary_attack_finds_zipcrypto_password() {
    let temp = TempDir::new("hit");
    let zip = temp.join("encrypted.zip");
    let dict = temp.join("dictionary.txt");
    write_zipcrypto_zip(&zip);
    write_dictionary(&dict, &["wrong1", PASSWORD, "wrong2"]);

    let output = acx()
        .arg("-f")
        .arg(&zip)
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
    assert!(stdout.contains("Encryption: zipcrypto"), "stdout: {stdout}");
}

#[test]
fn dictionary_attack_finds_aes_password() {
    let temp = TempDir::new("aes-hit");
    let zip = temp.join("encrypted-aes.zip");
    let dict = temp.join("dictionary.txt");
    write_aes_zip(&zip);
    write_dictionary(&dict, &["wrong1", PASSWORD, "wrong2"]);

    let output = acx()
        .arg("-f")
        .arg(&zip)
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
    assert!(stdout.contains("Encryption: aes"), "stdout: {stdout}");
}

#[test]
fn wrong_aes_dictionary_exits_one() {
    let temp = TempDir::new("aes-miss");
    let zip = temp.join("encrypted-aes.zip");
    let dict = temp.join("dictionary.txt");
    write_aes_zip(&zip);
    write_dictionary(&dict, &["wrong1", "wrong2", "wrong3"]);

    let output = acx()
        .arg("-f")
        .arg(&zip)
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
    assert_eq!(
        output.status.code(),
        Some(1),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(stdout.contains("NOT FOUND"), "stdout: {stdout}");
    assert!(!stdout.contains("FOUND: "), "stdout: {stdout}");
}

#[test]
fn wrong_dictionary_exits_one() {
    let temp = TempDir::new("miss");
    let zip = temp.join("encrypted.zip");
    let dict = temp.join("dictionary.txt");
    write_zipcrypto_zip(&zip);
    write_dictionary(&dict, &["wrong1", "wrong2", "wrong3"]);

    let output = acx()
        .arg("-f")
        .arg(&zip)
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
    assert_eq!(
        output.status.code(),
        Some(1),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(stdout.contains("NOT FOUND"), "stdout: {stdout}");
    assert!(!stdout.contains("FOUND: "), "stdout: {stdout}");
}

#[test]
fn empty_dictionary_exits_two() {
    let temp = TempDir::new("empty-dict");
    let zip = temp.join("encrypted.zip");
    let dict = temp.join("dictionary.txt");
    write_zipcrypto_zip(&zip);
    write_dictionary(&dict, &[]);

    let output = acx()
        .arg("-f")
        .arg(&zip)
        .arg("-d")
        .arg(&dict)
        .output()
        .expect("run acx");

    assert_eq!(
        output.status.code(),
        Some(2),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn mask_attack_finds_password_without_dictionary() {
    let temp = TempDir::new("mask-hit");
    let zip = temp.join("encrypted.zip");
    write_zipcrypto_zip(&zip);

    let output = acx()
        .arg("-f")
        .arg(&zip)
        .arg("--mask")
        .arg("P@ssw0rd?d?d?d")
        .arg("-t")
        .arg("4")
        .output()
        .expect("run acx mask");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(stdout.contains("FOUND: P@ssw0rd123"), "stdout: {stdout}");
}

#[test]
fn mask_custom_charset_finds_password() {
    let temp = TempDir::new("mask-custom");
    let zip = temp.join("encrypted.zip");
    write_zipcrypto_zip(&zip);

    let output = acx()
        .arg("-f")
        .arg(&zip)
        .arg("--mask")
        .arg("P@ssw0rd?1?1?1")
        .arg("--custom-charset1")
        .arg("?d")
        .arg("-t")
        .arg("4")
        .output()
        .expect("run acx custom mask");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(stdout.contains("FOUND: P@ssw0rd123"), "stdout: {stdout}");
}

#[test]
fn mask_estimate_prints_keyspace_without_attack() {
    let temp = TempDir::new("mask-estimate");
    let zip = temp.join("encrypted.zip");
    write_zipcrypto_zip(&zip);

    let output = acx()
        .arg("-f")
        .arg(&zip)
        .arg("--mask")
        .arg("?d?d?d")
        .arg("--estimate")
        .output()
        .expect("run acx estimate");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(stdout.contains("Keyspace: 1000"), "stdout: {stdout}");
    assert!(stdout.contains("24h capacity"), "stdout: {stdout}");
    assert!(!stdout.contains("FOUND:"), "stdout: {stdout}");
}

#[test]
fn mask_estimate_allows_unencrypted_archive() {
    let temp = TempDir::new("mask-estimate-plain");
    let zip = temp.join("plain.zip");
    write_plain_zip(&zip);

    let output = acx()
        .arg("-f")
        .arg(&zip)
        .arg("--mask")
        .arg("?d")
        .arg("--estimate")
        .output()
        .expect("run acx estimate");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(stdout.contains("Keyspace: 10"), "stdout: {stdout}");
}

#[test]
fn unencrypted_zip_exits_three() {
    let temp = TempDir::new("plain");
    let zip = temp.join("plain.zip");
    let dict = temp.join("dictionary.txt");
    write_plain_zip(&zip);
    write_dictionary(&dict, &[PASSWORD]);

    let output = acx()
        .arg("-f")
        .arg(&zip)
        .arg("-m")
        .arg("dict")
        .arg("-d")
        .arg(&dict)
        .arg("-t")
        .arg("1")
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
