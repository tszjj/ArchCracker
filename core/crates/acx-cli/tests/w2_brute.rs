// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

//! End-to-end tests for the W2-003 brute-force CLI path.
//!
//! Fixtures are generated at test time; no archive is committed.

use acx_core::archive::ArchiveSource;
use acx_core::candidates::BruteSet;
use acx_core::checkpoint::{ArchiveFingerprint, AttackFingerprint, Checkpoint, CheckpointStore};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use zip::unstable::write::FileOptionsExt;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

const HELLO: &[u8] = b"ArchCracker W2-003 brute fixture";

fn scratch_dir() -> &'static Path {
    static SCRATCH: OnceLock<PathBuf> = OnceLock::new();
    SCRATCH.get_or_init(|| {
        let preferred = std::env::temp_dir();
        let probe = preferred.join(format!("acx-cli-w2-003-probe-{}.tmp", std::process::id()));
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
            "acx-cli-w2-003-{tag}-{}-{nanos}-{id}",
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

fn acx() -> Command {
    Command::new(env!("CARGO_BIN_EXE_acx"))
}

fn brute_checkpoint(
    archive: &Path,
    charset: &str,
    custom: [Option<&str>; 4],
    min: usize,
    max: usize,
) -> Checkpoint {
    let source = ArchiveSource::resolve(archive).expect("resolve archive");
    let archive_fp = ArchiveFingerprint::from_source(&source).expect("archive fingerprint");
    let custom_texts = custom.map(|text| text.map(str::to_string));
    let set = BruteSet::parse(charset, &custom_texts, min, max).expect("brute set");
    let total = u64::try_from(set.keyspace()).expect("keyspace fits u64");
    let checkpoint = Checkpoint::new(
        archive_fp,
        None,
        AttackFingerprint::new("brute", set.signature()),
        1,
        0,
        0,
        total,
    );
    checkpoint
}

#[test]
fn brute_attack_finds_password() {
    let temp = TempDir::new("hit");
    let zip = temp.join("encrypted.zip");
    write_zipcrypto_zip(&zip, "a1");

    let output = acx()
        .arg("-f")
        .arg(&zip)
        .arg("--brute")
        .arg("?l?d")
        .arg("--min-len")
        .arg("2")
        .arg("--max-len")
        .arg("2")
        .arg("-t")
        .arg("4")
        .output()
        .expect("run acx brute");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(stdout.contains("FOUND: a1"), "stdout: {stdout}");
    assert!(stdout.contains("Brute keyspace: 1296"), "stdout: {stdout}");
}

#[test]
fn brute_custom_charset_finds_password() {
    let temp = TempDir::new("custom-charset");
    let zip = temp.join("encrypted.zip");
    write_zipcrypto_zip(&zip, "ab");

    let output = acx()
        .arg("-f")
        .arg(&zip)
        .arg("--brute")
        .arg("?1")
        .arg("--custom-charset1")
        .arg("ab")
        .arg("--min-len")
        .arg("2")
        .arg("--max-len")
        .arg("2")
        .arg("-t")
        .arg("2")
        .output()
        .expect("run acx brute custom");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(stdout.contains("FOUND: ab"), "stdout: {stdout}");
}

#[test]
fn brute_estimate_prints_per_length_keyspace_without_attack() {
    let temp = TempDir::new("estimate");
    let zip = temp.join("plain.zip");
    write_plain_zip(&zip);

    let output = acx()
        .arg("-f")
        .arg(&zip)
        .arg("--brute")
        .arg("?d")
        .arg("--min-len")
        .arg("1")
        .arg("--max-len")
        .arg("3")
        .arg("--estimate")
        .output()
        .expect("run acx brute estimate");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(stdout.contains("Keyspace: 1110"), "stdout: {stdout}");
    assert!(stdout.contains("Length 1: 10"), "stdout: {stdout}");
    assert!(stdout.contains("Length 3: 1000"), "stdout: {stdout}");
    assert!(stdout.contains("Watermark bitmap:"), "stdout: {stdout}");
    assert!(
        stdout.contains("Estimated peak (core):"),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("24h capacity"), "stdout: {stdout}");
    assert!(!stdout.contains("FOUND:"), "stdout: {stdout}");
}

#[test]
fn brute_resume_starts_at_a_length_boundary() {
    let temp = TempDir::new("resume-boundary");
    let zip = temp.join("encrypted.zip");
    let checkpoint_path = temp.join("run.acx-checkpoint");
    // "?l" length 1 has 26 candidates; watermark 26 must resume at length 2,
    // candidate 0 ("aa"), not skip into the middle of the first length.
    write_zipcrypto_zip(&zip, "aa");
    let mut checkpoint = brute_checkpoint(&zip, "?l", [None, None, None, None], 1, 2);
    checkpoint.completed_through = 26;
    checkpoint.tried = 30;
    CheckpointStore::new(checkpoint_path.clone())
        .save(&checkpoint)
        .expect("save checkpoint");

    let output = acx()
        .arg("-f")
        .arg(&zip)
        .arg("--brute")
        .arg("?l")
        .arg("--min-len")
        .arg("1")
        .arg("--max-len")
        .arg("2")
        .arg("--checkpoint")
        .arg(&checkpoint_path)
        .arg("--resume")
        .arg("-t")
        .arg("4")
        .output()
        .expect("run acx brute resume");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(stdout.contains("candidate 26/702"), "stdout: {stdout}");
    assert!(stdout.contains("FOUND: aa"), "stdout: {stdout}");
    assert!(
        !checkpoint_path.exists(),
        "checkpoint must be removed on hit"
    );
}

#[test]
fn brute_resume_rejects_a_changed_length_range() {
    let temp = TempDir::new("resume-mismatch");
    let zip = temp.join("encrypted.zip");
    let checkpoint_path = temp.join("run.acx-checkpoint");
    write_zipcrypto_zip(&zip, "aa");
    let checkpoint = brute_checkpoint(&zip, "?l", [None, None, None, None], 1, 2);
    CheckpointStore::new(checkpoint_path.clone())
        .save(&checkpoint)
        .expect("save checkpoint");

    let output = acx()
        .arg("-f")
        .arg(&zip)
        .arg("--brute")
        .arg("?l")
        .arg("--min-len")
        .arg("1")
        .arg("--max-len")
        .arg("3")
        .arg("--checkpoint")
        .arg(&checkpoint_path)
        .arg("--resume")
        .output()
        .expect("run acx brute resume");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "stderr: {stderr}");
    assert!(
        stderr.contains("attack signature changed"),
        "stderr: {stderr}"
    );
}

#[test]
fn brute_requires_a_length_range() {
    let temp = TempDir::new("missing-range");
    let zip = temp.join("encrypted.zip");
    write_zipcrypto_zip(&zip, "a1");

    let output = acx()
        .arg("-f")
        .arg(&zip)
        .arg("--brute")
        .arg("?d")
        .output()
        .expect("run acx brute");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "stderr: {stderr}");
    assert!(
        stderr.contains("requires --min-len and --max-len"),
        "stderr: {stderr}"
    );
}

#[test]
fn brute_rejects_mask_mode_combination() {
    let temp = TempDir::new("mixed-modes");
    let zip = temp.join("encrypted.zip");
    write_zipcrypto_zip(&zip, "a1");

    let output = acx()
        .arg("-f")
        .arg(&zip)
        .arg("--brute")
        .arg("?d")
        .arg("--mask")
        .arg("?d")
        .arg("--min-len")
        .arg("1")
        .arg("--max-len")
        .arg("2")
        .output()
        .expect("run acx brute");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "stderr: {stderr}");
    assert!(stderr.contains("mutually exclusive"), "stderr: {stderr}");
}

#[test]
fn brute_mode_without_charset_exits_two() {
    let temp = TempDir::new("mode-only");
    let zip = temp.join("encrypted.zip");
    write_zipcrypto_zip(&zip, "a1");

    let output = acx()
        .arg("-f")
        .arg(&zip)
        .arg("-m")
        .arg("brute")
        .output()
        .expect("run acx brute");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "stderr: {stderr}");
    assert!(stderr.contains("requires --brute"), "stderr: {stderr}");
}

#[test]
fn brute_attack_refuses_keyspace_above_usize() {
    let temp = TempDir::new("too-large");
    let zip = temp.join("encrypted.zip");
    write_zipcrypto_zip(&zip, "a1");

    let output = acx()
        .arg("-f")
        .arg(&zip)
        .arg("--brute")
        .arg("?a")
        .arg("--min-len")
        .arg("1")
        .arg("--max-len")
        .arg("10")
        .output()
        .expect("run acx brute");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "stderr: {stderr}");
    assert!(
        stderr.contains("cannot be executed with the current usize index limit"),
        "stderr: {stderr}"
    );
}

#[test]
fn brute_resume_rejects_a_changed_custom_charset() {
    let temp = TempDir::new("resume-custom");
    let zip = temp.join("encrypted.zip");
    let checkpoint_path = temp.join("run.acx-checkpoint");
    write_zipcrypto_zip(&zip, "ab");
    let checkpoint = brute_checkpoint(&zip, "?1", [Some("ab"), None, None, None], 1, 2);
    CheckpointStore::new(checkpoint_path.clone())
        .save(&checkpoint)
        .expect("save checkpoint");

    let output = acx()
        .arg("-f")
        .arg(&zip)
        .arg("--brute")
        .arg("?1")
        .arg("--custom-charset1")
        .arg("ac")
        .arg("--min-len")
        .arg("1")
        .arg("--max-len")
        .arg("2")
        .arg("--checkpoint")
        .arg(&checkpoint_path)
        .arg("--resume")
        .output()
        .expect("run acx brute resume");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "stderr: {stderr}");
    assert!(
        stderr.contains("attack signature changed"),
        "stderr: {stderr}"
    );
}

#[test]
fn brute_and_dictionary_are_mutually_exclusive() {
    let temp = TempDir::new("dict-exclusive");
    let zip = temp.join("encrypted.zip");
    write_zipcrypto_zip(&zip, "a1");

    let output = acx()
        .arg("-f")
        .arg(&zip)
        .arg("--brute")
        .arg("?d")
        .arg("--min-len")
        .arg("1")
        .arg("--max-len")
        .arg("2")
        .arg("-d")
        .arg(temp.join("dict.txt"))
        .output()
        .expect("run acx brute");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "stderr: {stderr}");
    assert!(
        stderr.contains("--dictionary and --brute are mutually exclusive"),
        "stderr: {stderr}"
    );
}

#[test]
fn length_flags_require_brute_mode() {
    let temp = TempDir::new("length-flags");
    let zip = temp.join("encrypted.zip");
    write_zipcrypto_zip(&zip, "a1");

    let output = acx()
        .arg("-f")
        .arg(&zip)
        .arg("-d")
        .arg(temp.join("dict.txt"))
        .arg("--min-len")
        .arg("1")
        .output()
        .expect("run acx");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "stderr: {stderr}");
    assert!(stderr.contains("require --brute"), "stderr: {stderr}");
}

#[test]
fn brute_estimate_warns_above_24h() {
    let temp = TempDir::new("estimate-24h");
    let zip = temp.join("plain.zip");
    write_plain_zip(&zip);

    let output = acx()
        .arg("-f")
        .arg(&zip)
        .arg("--brute")
        .arg("?l?d")
        .arg("--min-len")
        .arg("1")
        .arg("--max-len")
        .arg("8")
        .arg("--estimate")
        .output()
        .expect("run acx brute estimate");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(stderr.contains("exceeds 24h"), "stderr: {stderr}");
    assert!(
        !stdout.contains("FOUND:"),
        "estimate must not run the attack: {stdout}"
    );
}

#[test]
fn brute_estimate_still_reports_keyspace_above_usize() {
    let temp = TempDir::new("estimate-too-large");
    let zip = temp.join("plain.zip");
    write_plain_zip(&zip);

    let output = acx()
        .arg("-f")
        .arg(&zip)
        .arg("--brute")
        .arg("?a")
        .arg("--min-len")
        .arg("1")
        .arg("--max-len")
        .arg("10")
        .arg("--estimate")
        .output()
        .expect("run acx brute estimate");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("Fits executable index: false"),
        "stdout: {stdout}"
    );
    assert!(
        stderr.contains("only estimation is possible"),
        "stderr: {stderr}"
    );
}
