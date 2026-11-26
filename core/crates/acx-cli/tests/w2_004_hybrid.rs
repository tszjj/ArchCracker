// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

//! End-to-end tests for the W2-004 hybrid CLI path (rules + affix masks).

use acx_core::archive::ArchiveSource;
use acx_core::candidates::HybridSet;
use acx_core::checkpoint::{
    ArchiveFingerprint, AttackFingerprint, Checkpoint, CheckpointStore, FileFingerprint,
};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use zip::unstable::write::FileOptionsExt;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

const HELLO: &[u8] = b"ArchCracker W2-004 hybrid fixture";

fn scratch_dir() -> &'static Path {
    static SCRATCH: OnceLock<PathBuf> = OnceLock::new();
    SCRATCH.get_or_init(|| {
        let preferred = std::env::temp_dir();
        let probe = preferred.join(format!("acx-cli-w2-004-probe-{}.tmp", std::process::id()));
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
            "acx-cli-w2-004-{tag}-{}-{nanos}-{id}",
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

fn write_zipcrypto_zip(path: &Path, password: &str) {
    let file = std::fs::File::create(path)
        .unwrap_or_else(|error| panic!("create {}: {error}", path.display()));
    let mut writer = ZipWriter::new(file);
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .with_deprecated_encryption(password.as_bytes())
        .expect("ZipCrypto file options");
    writer
        .start_file("hello.txt", options)
        .expect("start hello.txt");
    writer.write_all(HELLO).expect("write hello.txt");
    writer.finish().expect("finish encrypted zip");
}

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
    std::fs::write(path, contents).expect("write dictionary");
}

fn acx() -> Command {
    Command::new(env!("CARGO_BIN_EXE_acx"))
}

fn hybrid_checkpoint(
    archive: &Path,
    dictionary: &Path,
    rules: &[&str],
    suffix: Option<&str>,
    completed_through: u64,
    total: u64,
) -> Checkpoint {
    let source = ArchiveSource::resolve(archive).expect("resolve archive");
    let archive_fp = ArchiveFingerprint::from_source(&source).expect("archive fingerprint");
    let dictionary_fp = FileFingerprint::from_path(dictionary).expect("dictionary fingerprint");
    let rule_texts: Vec<String> = rules.iter().map(|rule| (*rule).to_string()).collect();
    let set = HybridSet::parse(
        dictionary,
        &rule_texts,
        None,
        suffix,
        &[None, None, None, None],
    )
    .expect("hybrid set");
    Checkpoint::new(
        archive_fp,
        Some(dictionary_fp),
        AttackFingerprint::new("hybrid", set.signature()),
        1,
        completed_through,
        completed_through + 5,
        total,
    )
}

#[test]
fn hybrid_rule_finds_password() {
    let temp = TempDir::new("rule-hit");
    let zip = temp.join("encrypted.zip");
    let dictionary = temp.join("words.txt");
    write_zipcrypto_zip(&zip, "Acme123");
    write_dictionary(&dictionary, &["acme", "other"]);

    let output = acx()
        .arg("-f")
        .arg(&zip)
        .arg("-d")
        .arg(&dictionary)
        .arg("--rule")
        .arg("identity")
        .arg("--rule")
        .arg("capitalize|append:123")
        .arg("-t")
        .arg("2")
        .output()
        .expect("run acx hybrid");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(stdout.contains("FOUND: Acme123"), "stdout: {stdout}");
    assert!(stdout.contains("Variants per line: 2"), "stdout: {stdout}");
    assert!(stdout.contains("Watermark bitmap:"), "stdout: {stdout}");
}

#[test]
fn hybrid_suffix_mask_finds_password() {
    let temp = TempDir::new("suffix-hit");
    let zip = temp.join("encrypted.zip");
    let dictionary = temp.join("words.txt");
    write_zipcrypto_zip(&zip, "acme42");
    write_dictionary(&dictionary, &["acme"]);

    let output = acx()
        .arg("-f")
        .arg(&zip)
        .arg("-d")
        .arg(&dictionary)
        .arg("--suffix-mask")
        .arg("?d?d")
        .arg("-t")
        .arg("2")
        .output()
        .expect("run acx hybrid");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(stdout.contains("FOUND: acme42"), "stdout: {stdout}");
    assert!(
        stdout.contains("Variants per line: 101"),
        "stdout: {stdout}"
    );
}

#[test]
fn hybrid_prefix_and_suffix_combine() {
    let temp = TempDir::new("affix-hit");
    let zip = temp.join("encrypted.zip");
    let dictionary = temp.join("words.txt");
    write_zipcrypto_zip(&zip, "Xacme4");
    write_dictionary(&dictionary, &["acme"]);

    let output = acx()
        .arg("-f")
        .arg(&zip)
        .arg("-d")
        .arg(&dictionary)
        .arg("--prefix-mask")
        .arg("X")
        .arg("--suffix-mask")
        .arg("?d")
        .arg("-t")
        .arg("2")
        .output()
        .expect("run acx hybrid");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(stdout.contains("FOUND: Xacme4"), "stdout: {stdout}");
    assert!(stdout.contains("Variants per line: 11"), "stdout: {stdout}");
}

#[test]
fn hybrid_estimate_prints_space_without_attack() {
    let temp = TempDir::new("estimate");
    let zip = temp.join("plain.zip");
    let dictionary = temp.join("words.txt");
    write_plain_zip(&zip);
    write_dictionary(&dictionary, &["one", "two", "three"]);

    let output = acx()
        .arg("-f")
        .arg(&zip)
        .arg("-d")
        .arg(&dictionary)
        .arg("--suffix-mask")
        .arg("?d")
        .arg("--estimate")
        .output()
        .expect("run acx hybrid estimate");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(stdout.contains("Dictionary lines: 3"), "stdout: {stdout}");
    assert!(stdout.contains("Variants per line: 11"), "stdout: {stdout}");
    assert!(stdout.contains("Total candidates: 33"), "stdout: {stdout}");
    assert!(stdout.contains("Watermark bitmap:"), "stdout: {stdout}");
    assert!(
        stdout.contains("Estimated peak (core):"),
        "stdout: {stdout}"
    );
    assert!(!stdout.contains("FOUND:"), "stdout: {stdout}");
}

#[test]
fn hybrid_resume_starts_at_a_line_boundary() {
    let temp = TempDir::new("resume");
    let zip = temp.join("encrypted.zip");
    let dictionary = temp.join("words.txt");
    let checkpoint_path = temp.join("run.acx-checkpoint");
    write_zipcrypto_zip(&zip, "two");
    write_dictionary(&dictionary, &["one", "two"]);
    // V = 1 (identity) + 10 (suffix ?d) = 11; line 2 starts at index 11.
    let checkpoint = hybrid_checkpoint(&zip, &dictionary, &["identity"], Some("?d"), 11, 22);
    CheckpointStore::new(checkpoint_path.clone())
        .save(&checkpoint)
        .expect("save checkpoint");

    let output = acx()
        .arg("-f")
        .arg(&zip)
        .arg("-d")
        .arg(&dictionary)
        .arg("--suffix-mask")
        .arg("?d")
        .arg("--checkpoint")
        .arg(&checkpoint_path)
        .arg("--resume")
        .arg("-t")
        .arg("2")
        .output()
        .expect("run acx hybrid resume");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(stdout.contains("candidate 11/22"), "stdout: {stdout}");
    assert!(stdout.contains("FOUND: two"), "stdout: {stdout}");
    assert!(
        !checkpoint_path.exists(),
        "checkpoint must be removed on hit"
    );
}

#[test]
fn hybrid_resume_rejects_a_changed_rule() {
    let temp = TempDir::new("resume-mismatch");
    let zip = temp.join("encrypted.zip");
    let dictionary = temp.join("words.txt");
    let checkpoint_path = temp.join("run.acx-checkpoint");
    write_zipcrypto_zip(&zip, "one");
    write_dictionary(&dictionary, &["ONE"]);
    let checkpoint = hybrid_checkpoint(&zip, &dictionary, &["lower"], None, 0, 1);
    CheckpointStore::new(checkpoint_path.clone())
        .save(&checkpoint)
        .expect("save checkpoint");

    let output = acx()
        .arg("-f")
        .arg(&zip)
        .arg("-d")
        .arg(&dictionary)
        .arg("--rule")
        .arg("upper")
        .arg("--checkpoint")
        .arg(&checkpoint_path)
        .arg("--resume")
        .output()
        .expect("run acx hybrid resume");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "stderr: {stderr}");
    assert!(
        stderr.contains("attack signature changed"),
        "stderr: {stderr}"
    );
}

#[test]
fn hybrid_requires_a_dictionary() {
    let temp = TempDir::new("missing-dict");
    let zip = temp.join("encrypted.zip");
    write_zipcrypto_zip(&zip, "one");

    let output = acx()
        .arg("-f")
        .arg(&zip)
        .arg("--rule")
        .arg("identity")
        .output()
        .expect("run acx hybrid");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "stderr: {stderr}");
    assert!(
        stderr.contains("hybrid mode requires --dictionary"),
        "stderr: {stderr}"
    );
}

#[test]
fn hybrid_mode_requires_a_variant() {
    let temp = TempDir::new("missing-variant");
    let zip = temp.join("encrypted.zip");
    let dictionary = temp.join("words.txt");
    write_zipcrypto_zip(&zip, "one");
    write_dictionary(&dictionary, &["one"]);

    let output = acx()
        .arg("-f")
        .arg(&zip)
        .arg("-d")
        .arg(&dictionary)
        .arg("-m")
        .arg("hybrid")
        .output()
        .expect("run acx hybrid");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "stderr: {stderr}");
    assert!(
        stderr.contains("requires --rule, --prefix-mask, or --suffix-mask"),
        "stderr: {stderr}"
    );
}

#[test]
fn hybrid_rejects_mask_mode_combination() {
    let temp = TempDir::new("mixed");
    let zip = temp.join("encrypted.zip");
    let dictionary = temp.join("words.txt");
    write_zipcrypto_zip(&zip, "one");
    write_dictionary(&dictionary, &["one"]);

    let output = acx()
        .arg("-f")
        .arg(&zip)
        .arg("-d")
        .arg(&dictionary)
        .arg("--rule")
        .arg("identity")
        .arg("--mask")
        .arg("?d")
        .output()
        .expect("run acx hybrid");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "stderr: {stderr}");
    assert!(stderr.contains("mutually exclusive"), "stderr: {stderr}");
}
