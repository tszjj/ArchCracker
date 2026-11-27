// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

//! End-to-end tests for W2-007 unified fast-filter counters and strict mode.

use sevenz_rust2::encoder_options::AesEncoderOptions;
use sevenz_rust2::{ArchiveEntry, ArchiveWriter, EncoderConfiguration, EncoderMethod, Password};
use std::io::Cursor;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use zip::unstable::write::FileOptionsExt;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

const HELLO: &[u8] = b"ArchCracker W2-007 filter fixture";

fn scratch_dir() -> &'static Path {
    static SCRATCH: OnceLock<PathBuf> = OnceLock::new();
    SCRATCH.get_or_init(|| {
        let preferred = std::env::temp_dir();
        let probe = preferred.join(format!("acx-cli-w2-007-probe-{}.tmp", std::process::id()));
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
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or(0);
        let path = scratch_dir().join(format!(
            "acx-cli-w2-007-{tag}-{}-{nanos}-{id}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
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

fn write_zipcrypto_zip(path: &Path, password: &[u8]) {
    let file =
        std::fs::File::create(path).unwrap_or_else(|e| panic!("create {}: {e}", path.display()));
    let mut writer = ZipWriter::new(file);
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .with_deprecated_encryption(password)
        .expect("ZipCrypto options");
    writer
        .start_file("hello.txt", options)
        .expect("start entry");
    writer.write_all(HELLO).expect("write entry");
    writer.finish().expect("finish zip");
}

fn write_encrypted_7z(path: &Path, password: &str) {
    let mut writer = ArchiveWriter::create(path).expect("create 7z");
    let mut methods = vec![EncoderConfiguration::new(EncoderMethod::LZMA2)];
    methods.push(AesEncoderOptions::new(Password::from(password)).into());
    writer.set_content_methods(methods);
    writer
        .push_archive_entry(
            ArchiveEntry::new_file("hello.txt"),
            Some(Cursor::new(HELLO.to_vec())),
        )
        .expect("push entry");
    writer.finish().expect("finish 7z");
}

fn write_dictionary(path: &Path, lines: &[&str]) {
    let mut body = lines.join("\n");
    body.push('\n');
    std::fs::write(path, body).expect("write dictionary");
}

fn acx() -> Command {
    Command::new(env!("CARGO_BIN_EXE_acx"))
}

/// Read a numeric counter from a `Stats:` line.
fn stat(stdout: &str, key: &str) -> u64 {
    let marker = format!("{key}=");
    let rest = stdout
        .split_once(&marker)
        .unwrap_or_else(|| panic!("missing `{key}` in stats: {stdout}"))
        .1;
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits
        .parse()
        .unwrap_or_else(|_| panic!("bad `{key}` value: {stdout}"))
}

fn assert_attempts_formula(stdout: &str) {
    let attempts = stat(stdout, "encoding attempts");
    let fast = stat(stdout, "fast rejects");
    let full = stat(stdout, "full attempted");
    assert_eq!(attempts, fast + full, "attempts equation broken: {stdout}");
}

#[test]
fn zip_wrong_candidates_are_counted_by_the_verifier_filter() {
    let temp = TempDir::new("zip-miss");
    write_zipcrypto_zip(&temp.join("a.zip"), b"correct-horse");
    write_dictionary(
        &temp.join("d.txt"),
        &["wrong-one", "wrong-two", "wrong-three"],
    );

    let output = acx()
        .arg("-f")
        .arg(temp.join("a.zip"))
        .arg("-d")
        .arg(temp.join("d.txt"))
        .arg("--report-stats")
        .output()
        .expect("run acx");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(1), "stdout: {stdout}");
    assert_eq!(stat(&stdout, "encoding attempts"), 3);
    assert_eq!(stat(&stdout, "zip_verifier"), stat(&stdout, "fast rejects"));
    assert_eq!(stat(&stdout, "sevenz_first_block"), 0);
    assert_eq!(stat(&stdout, "rar5_check_value"), 0);
    assert_eq!(stat(&stdout, "external attempts"), 0);
    assert!(stat(&stdout, "fast rejects") >= 1, "stdout: {stdout}");
    assert_attempts_formula(&stdout);
}

#[test]
fn zip_hit_keeps_full_attempt_and_formula() {
    let temp = TempDir::new("zip-hit");
    write_zipcrypto_zip(&temp.join("a.zip"), b"correct-horse");
    write_dictionary(&temp.join("d.txt"), &["wrong-one", "correct-horse"]);

    let output = acx()
        .arg("-f")
        .arg(temp.join("a.zip"))
        .arg("-d")
        .arg(temp.join("d.txt"))
        .arg("--report-stats")
        .output()
        .expect("run acx");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(0), "stdout: {stdout}");
    assert!(stdout.contains("FOUND: correct-horse"), "stdout: {stdout}");
    assert!(stat(&stdout, "full attempted") >= 1, "stdout: {stdout}");
    assert_eq!(stat(&stdout, "external attempts"), 0);
    assert_attempts_formula(&stdout);
}

#[test]
fn sevenz_default_counts_first_block_probe() {
    let temp = TempDir::new("7z-default");
    write_encrypted_7z(&temp.join("a.7z"), "correct-horse");
    write_dictionary(&temp.join("d.txt"), &["wrong-one", "wrong-two"]);

    let output = acx()
        .arg("-f")
        .arg(temp.join("a.7z"))
        .arg("-d")
        .arg(temp.join("d.txt"))
        .arg("--report-stats")
        .output()
        .expect("run acx");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(1), "stdout: {stdout}");
    assert_eq!(
        stat(&stdout, "sevenz_first_block"),
        stat(&stdout, "fast rejects")
    );
    assert_eq!(stat(&stdout, "zip_verifier"), 0);
    assert_attempts_formula(&stdout);
}

#[test]
fn sevenz_strict_disables_the_probe() {
    let temp = TempDir::new("7z-strict");
    write_encrypted_7z(&temp.join("a.7z"), "correct-horse");
    write_dictionary(&temp.join("d.txt"), &["wrong-one", "wrong-two"]);

    let output = acx()
        .arg("-f")
        .arg(temp.join("a.7z"))
        .arg("-d")
        .arg(temp.join("d.txt"))
        .arg("--strict")
        .arg("--report-stats")
        .output()
        .expect("run acx");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(1), "stdout: {stdout}");
    assert_eq!(stat(&stdout, "fast rejects"), 0);
    assert_eq!(stat(&stdout, "sevenz_first_block"), 0);
    assert_eq!(stat(&stdout, "full attempted"), 2);
    assert_attempts_formula(&stdout);
}

#[test]
fn batch_report_exposes_the_new_counter_fields() {
    let temp = TempDir::new("batch");
    write_zipcrypto_zip(&temp.join("a.zip"), b"correct-horse");
    write_dictionary(&temp.join("d.txt"), &["correct-horse"]);
    std::fs::write(
        temp.join("jobs.toml"),
        r#"
max_parallel = 1

[[jobs]]
id = "filters"
archive = "a.zip"
mode = "dict"
dictionary = "d.txt"
report_stats = true
"#,
    )
    .expect("write manifest");

    let output = acx()
        .arg("batch")
        .arg(temp.join("jobs.toml"))
        .output()
        .expect("run acx batch");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(0), "stdout: {stdout}");
    assert!(stdout.contains("[filters] Stats:"), "stdout: {stdout}");
    assert!(stdout.contains("full attempted="), "stdout: {stdout}");
    assert!(stdout.contains("external attempts="), "stdout: {stdout}");
    assert_attempts_formula(&stdout);
}
