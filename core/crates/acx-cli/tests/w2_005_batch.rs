// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

//! End-to-end tests for W2-005 batch manifests.

use acx_core::archive::ArchiveSource;
use acx_core::checkpoint::{
    ArchiveFingerprint, AttackFingerprint, Checkpoint, CheckpointStore, FileFingerprint,
};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use zip::unstable::write::FileOptionsExt;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

const HELLO: &[u8] = b"ArchCracker W2-005 batch fixture";

fn scratch_dir() -> &'static Path {
    static SCRATCH: OnceLock<PathBuf> = OnceLock::new();
    SCRATCH.get_or_init(|| {
        let preferred = std::env::temp_dir();
        let probe = preferred.join(format!("acx-cli-w2-005-probe-{}.tmp", std::process::id()));
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
            "acx-cli-w2-005-{tag}-{}-{nanos}-{id}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }

    fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    fn path(&self) -> &Path {
        &self.path
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

fn write_dictionary(path: &Path, lines: &[&str]) {
    let mut body = lines.join("\n");
    body.push('\n');
    std::fs::write(path, body).expect("write dictionary");
}

fn acx() -> Command {
    Command::new(env!("CARGO_BIN_EXE_acx"))
}

fn run_batch(dir: &Path, extra: &[&str]) -> Output {
    acx()
        .arg("batch")
        .arg(dir.join("jobs.toml"))
        .args(extra)
        .output()
        .expect("run acx batch")
}

fn write_manifest(dir: &TempDir, body: &str) {
    std::fs::write(dir.join("jobs.toml"), body).expect("write manifest");
}

#[test]
fn batch_isolates_hit_miss_and_bad_archive() {
    let temp = TempDir::new("isolation");
    write_zipcrypto_zip(&temp.join("hit.zip"), "one");
    write_dictionary(&temp.join("hit.txt"), &["one"]);
    write_zipcrypto_zip(&temp.join("miss.zip"), "secret");
    write_dictionary(&temp.join("miss.txt"), &["wrong"]);
    std::fs::write(temp.join("bad.zip"), b"not a zip").expect("write bad archive");
    write_manifest(
        &temp,
        r#"
max_parallel = 1

[[jobs]]
id = "hit"
archive = "hit.zip"
mode = "dict"
dictionary = "hit.txt"

[[jobs]]
id = "miss"
archive = "miss.zip"
mode = "dict"
dictionary = "miss.txt"

[[jobs]]
id = "bad"
archive = "bad.zip"
mode = "dict"
dictionary = "miss.txt"
"#,
    );

    let output = run_batch(temp.path(), &[]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(3),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(stdout.contains("[hit] FOUND: one"), "stdout: {stdout}");
    assert!(stdout.contains("[miss] NOT FOUND"), "stdout: {stdout}");
    assert!(stderr.contains("[bad] FAILED:"), "stderr: {stderr}");
    assert!(
        stdout.contains("Batch summary: 1 found, 1 not found, 1 failed"),
        "stdout: {stdout}"
    );
    // The good tasks completed despite the bad archive.
    assert!(!temp
        .join("acx-checkpoints")
        .join("hit.acx-checkpoint")
        .exists());
    assert!(!temp
        .join("acx-checkpoints")
        .join("miss.acx-checkpoint")
        .exists());
}

#[test]
fn batch_runs_in_parallel_and_returns_zero_when_all_hit() {
    let temp = TempDir::new("parallel");
    for (name, password) in [("a", "alpha"), ("b", "beta")] {
        write_zipcrypto_zip(&temp.join(&format!("{name}.zip")), password);
        write_dictionary(&temp.join(&format!("{name}.txt")), &[password]);
    }
    write_manifest(
        &temp,
        r#"
max_parallel = 2

[[jobs]]
id = "a"
archive = "a.zip"
mode = "dict"
dictionary = "a.txt"
threads = 2

[[jobs]]
id = "b"
archive = "b.zip"
mode = "dict"
dictionary = "b.txt"
threads = 2
"#,
    );

    let output = run_batch(temp.path(), &[]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(stdout.contains("[a] FOUND: alpha"), "stdout: {stdout}");
    assert!(stdout.contains("[b] FOUND: beta"), "stdout: {stdout}");
    assert!(
        stdout.contains("Batch summary: 2 found, 0 not found, 0 failed"),
        "stdout: {stdout}"
    );
}

#[test]
fn batch_dry_run_does_not_start_attacks_or_write_checkpoints() {
    let temp = TempDir::new("dry-run");
    write_zipcrypto_zip(&temp.join("hit.zip"), "one");
    write_dictionary(&temp.join("hit.txt"), &["one"]);
    write_manifest(
        &temp,
        r#"
[[jobs]]
id = "hit"
archive = "hit.zip"
mode = "dict"
dictionary = "hit.txt"
"#,
    );

    let output = run_batch(temp.path(), &["--dry-run"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(stdout.contains("Task: hit"), "stdout: {stdout}");
    assert!(stdout.contains("Watermark bitmap:"), "stdout: {stdout}");
    assert!(stdout.contains("Batch estimate:"), "stdout: {stdout}");
    assert!(!stdout.contains("FOUND:"), "stdout: {stdout}");
    assert!(
        !temp.join("acx-checkpoints").exists(),
        "dry-run must not create a checkpoint root"
    );
}

#[test]
fn batch_reuse_found_shares_only_confirmed_passwords() {
    let temp = TempDir::new("reuse");
    write_zipcrypto_zip(&temp.join("first.zip"), "shared");
    write_dictionary(&temp.join("first.txt"), &["shared"]);
    write_zipcrypto_zip(&temp.join("second.zip"), "shared");
    write_dictionary(&temp.join("second.txt"), &["wrong"]);
    write_manifest(
        &temp,
        r#"
max_parallel = 1
reuse_found = true

[[jobs]]
id = "first"
archive = "first.zip"
mode = "dict"
dictionary = "first.txt"

[[jobs]]
id = "second"
archive = "second.zip"
mode = "dict"
dictionary = "second.txt"
"#,
    );

    let output = run_batch(temp.path(), &[]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("[second] FOUND: shared (reused)"),
        "stdout: {stdout}"
    );

    // A per-job disable wins over the manifest-wide switch.
    let temp2 = TempDir::new("reuse-disabled");
    write_zipcrypto_zip(&temp2.join("first.zip"), "shared");
    write_dictionary(&temp2.join("first.txt"), &["shared"]);
    write_zipcrypto_zip(&temp2.join("second.zip"), "shared");
    write_dictionary(&temp2.join("second.txt"), &["wrong"]);
    write_manifest(
        &temp2,
        r#"
reuse_found = true

[[jobs]]
id = "first"
archive = "first.zip"
mode = "dict"
dictionary = "first.txt"

[[jobs]]
id = "second"
archive = "second.zip"
mode = "dict"
dictionary = "second.txt"
reuse_found = false
"#,
    );
    let output = run_batch(temp2.path(), &[]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("[second] NOT FOUND"), "stdout: {stdout}");
    assert!(!stdout.contains("(reused)"), "stdout: {stdout}");
}

#[test]
fn batch_fail_fast_cancels_pending_jobs() {
    let temp = TempDir::new("fail-fast");
    std::fs::write(temp.join("bad.zip"), b"not a zip").expect("write bad archive");
    write_zipcrypto_zip(&temp.join("hit.zip"), "one");
    write_dictionary(&temp.join("hit.txt"), &["one"]);
    write_manifest(
        &temp,
        r#"
max_parallel = 1

[[jobs]]
id = "bad"
archive = "bad.zip"
mode = "dict"
dictionary = "hit.txt"

[[jobs]]
id = "hit"
archive = "hit.zip"
mode = "dict"
dictionary = "hit.txt"
"#,
    );

    let output = run_batch(temp.path(), &["--fail-fast"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(3),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(stderr.contains("[bad] FAILED:"), "stderr: {stderr}");
    assert!(stdout.contains("[hit] CANCELLED"), "stdout: {stdout}");
}

#[test]
fn batch_checkpoints_are_per_task_and_resume_independently() {
    let temp = TempDir::new("resume");
    write_zipcrypto_zip(&temp.join("a.zip"), "first");
    write_dictionary(&temp.join("a.txt"), &["first", "other"]);
    write_zipcrypto_zip(&temp.join("b.zip"), "second");
    write_dictionary(&temp.join("b.txt"), &["other", "second"]);
    write_manifest(
        &temp,
        r#"
max_parallel = 1
checkpoint_root = "runs"

[[jobs]]
id = "a"
archive = "a.zip"
mode = "dict"
dictionary = "a.txt"

[[jobs]]
id = "b"
archive = "b.zip"
mode = "dict"
dictionary = "b.txt"
"#,
    );

    let runs = temp.join("runs");
    std::fs::create_dir_all(&runs).expect("create runs");
    write_dictionary_checkpoint(
        &temp.join("a.zip"),
        &temp.join("a.txt"),
        &runs.join("a.acx-checkpoint"),
        1,
    );
    write_dictionary_checkpoint(
        &temp.join("b.zip"),
        &temp.join("b.txt"),
        &runs.join("b.acx-checkpoint"),
        0,
    );

    let output = run_batch(temp.path(), &[]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    // A skips its already-tested first candidate and misses; B starts at 0 and hits.
    assert!(stdout.contains("[a] NOT FOUND"), "stdout: {stdout}");
    assert!(stdout.contains("[b] FOUND: second"), "stdout: {stdout}");
    assert!(!runs.join("a.acx-checkpoint").exists());
    assert!(!runs.join("b.acx-checkpoint").exists());
}

fn write_dictionary_checkpoint(archive: &Path, dictionary: &Path, path: &Path, watermark: u64) {
    // Match the batch resolver, which canonicalizes the manifest directory.
    let archive = std::fs::canonicalize(archive).expect("canonicalize archive");
    let dictionary = std::fs::canonicalize(dictionary).expect("canonicalize dictionary");
    let source = ArchiveSource::resolve(&archive).expect("resolve archive");
    let archive_fp = ArchiveFingerprint::from_source(&source).expect("archive fingerprint");
    let dictionary_fp = FileFingerprint::from_path(&dictionary).expect("dictionary fingerprint");
    let checkpoint = Checkpoint::new(
        archive_fp,
        Some(dictionary_fp),
        AttackFingerprint::dictionary(),
        1,
        watermark,
        watermark,
        2,
    );
    CheckpointStore::new(path.to_path_buf())
        .save(&checkpoint)
        .expect("save checkpoint");
}

#[test]
fn batch_dry_run_covers_all_four_modes() {
    let temp = TempDir::new("four-modes");
    write_zipcrypto_zip(&temp.join("a.zip"), "one");
    write_dictionary(&temp.join("d.txt"), &["one", "other"]);
    write_manifest(
        &temp,
        r#"
[[jobs]]
id = "dict"
archive = "a.zip"
mode = "dict"
dictionary = "d.txt"

[[jobs]]
id = "mask"
archive = "a.zip"
mode = "mask"
masks = ["?d?d"]

[[jobs]]
id = "brute"
archive = "a.zip"
mode = "brute"
charset = "?l"
min_len = 1
max_len = 2

[[jobs]]
id = "hybrid"
archive = "a.zip"
mode = "hybrid"
dictionary = "d.txt"
rules = ["identity"]
suffix_mask = "?d"
"#,
    );
    let output = run_batch(temp.path(), &["--dry-run"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    for id in ["dict", "mask", "brute", "hybrid"] {
        assert!(stdout.contains(&format!("Task: {id}")), "stdout: {stdout}");
    }
    assert!(stdout.contains("Passwords: 2"), "stdout: {stdout}");
    assert!(stdout.contains("Keyspace: 100"), "stdout: {stdout}");
    assert!(stdout.contains("Lengths: 1..=2"), "stdout: {stdout}");
    assert!(stdout.contains("Variants per line: 11"), "stdout: {stdout}");
    assert!(
        stdout.contains("Batch estimate: 4 jobs"),
        "stdout: {stdout}"
    );
}

#[test]
fn batch_manifest_error_exits_two_without_running() {
    let temp = TempDir::new("bad-manifest");
    write_manifest(
        &temp,
        r#"
[[jobs]]
id = "a"
archive = "a.zip"
mode = "dict"
"#,
    );
    let output = run_batch(temp.path(), &[]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "stderr: {stderr}");
    assert!(stderr.contains("requires `dictionary`"), "stderr: {stderr}");
    assert!(!temp.join("acx-checkpoints").exists());
}

#[test]
fn batch_missing_archive_fails_validation_before_running() {
    let temp = TempDir::new("missing-archive");
    write_dictionary(&temp.join("d.txt"), &["one"]);
    write_manifest(
        &temp,
        r#"
[[jobs]]
id = "missing"
archive = "missing.zip"
mode = "dict"
dictionary = "d.txt"
"#,
    );
    let output = run_batch(temp.path(), &[]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "stderr: {stderr}");
    assert!(stderr.contains("job `missing`"), "stderr: {stderr}");
    assert!(!temp.join("acx-checkpoints").exists());
}

#[test]
fn batch_rejects_single_task_flags() {
    let temp = TempDir::new("mixed-cli");
    write_manifest(
        &temp,
        "[[jobs]]\nid = \"a\"\narchive = \"a.zip\"\nmode = \"dict\"\ndictionary = \"d.txt\"\n",
    );
    let output = acx()
        .arg("-f")
        .arg(temp.join("a.zip"))
        .arg("batch")
        .arg(temp.join("jobs.toml"))
        .output()
        .expect("run acx");
    assert_eq!(output.status.code(), Some(2));
}
