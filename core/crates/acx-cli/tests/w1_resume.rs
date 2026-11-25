// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

//! CLI resume/checkpoint integration test.

use acx_core::archive::ArchiveSource;
use acx_core::checkpoint::{ArchiveFingerprint, Checkpoint, CheckpointStore, FileFingerprint};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use zip::unstable::write::FileOptionsExt;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

const PASSWORD: &str = "P@ssw0rd123";
const HELLO: &[u8] = b"ArchCracker W1-006 resume fixture";

fn scratch_dir() -> &'static Path {
    static SCRATCH: OnceLock<PathBuf> = OnceLock::new();
    SCRATCH.get_or_init(|| {
        let preferred = std::env::temp_dir();
        let probe = preferred.join(format!("acx-cli-w1-006-probe-{}.tmp", std::process::id()));
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
            "acx-cli-w1-006-{tag}-{}-{nanos}-{id}",
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

fn write_zip(path: &Path) {
    let file = std::fs::File::create(path).expect("create zip");
    let mut writer = ZipWriter::new(file);
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .with_deprecated_encryption(PASSWORD.as_bytes())
        .expect("ZipCrypto options");
    writer.start_file("hello.txt", options).expect("start");
    writer.write_all(HELLO).expect("write");
    writer.finish().expect("finish");
}

fn write_dictionary(path: &Path, lines: &[&str]) {
    let mut contents = lines.join("\n");
    contents.push('\n');
    std::fs::write(path, contents).expect("write dictionary");
}

fn acx() -> Command {
    Command::new(env!("CARGO_BIN_EXE_acx"))
}

fn checkpoint_for(archive: &Path, dictionary: &Path, total: u64) -> Checkpoint {
    let source = ArchiveSource::resolve(archive).expect("resolve archive");
    let archive_fp = ArchiveFingerprint::from_source(&source).expect("archive fingerprint");
    let dictionary_fp = FileFingerprint::from_path(dictionary).expect("dictionary fingerprint");
    Checkpoint::new(archive_fp, dictionary_fp, "dict", 1, 1, 1, total)
}

#[test]
fn resume_starts_after_the_checkpoint_watermark() {
    let temp = TempDir::new("resume");
    let archive = temp.join("encrypted.zip");
    let dictionary = temp.join("dict.txt");
    let checkpoint_path = temp.join("run.acx-checkpoint");
    write_zip(&archive);
    write_dictionary(&dictionary, &["wrong", PASSWORD]);
    let checkpoint = checkpoint_for(&archive, &dictionary, 2);
    CheckpointStore::new(checkpoint_path.clone())
        .save(&checkpoint)
        .expect("save checkpoint");

    let output = acx()
        .arg("-f")
        .arg(&archive)
        .arg("-d")
        .arg(&dictionary)
        .arg("--checkpoint")
        .arg(&checkpoint_path)
        .arg("--resume")
        .output()
        .expect("run acx");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "exit {:?}\nstdout: {stdout}\nstderr: {stderr}",
        output.status.code()
    );
    assert!(stdout.contains("Resume:"), "stdout: {stdout}");
    assert!(stdout.contains("FOUND:"), "stdout: {stdout}");
    assert!(
        !checkpoint_path.exists(),
        "checkpoint must be removed on hit"
    );
}

#[test]
fn missing_dictionary_exits_two() {
    let temp = TempDir::new("missing-dict");
    let archive = temp.join("encrypted.zip");
    write_zip(&archive);
    let missing = temp.join("does-not-exist.txt");

    let output = acx()
        .arg("-f")
        .arg(&archive)
        .arg("-d")
        .arg(&missing)
        .output()
        .expect("run acx");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "stderr: {stderr}");
}

#[test]
fn resume_starts_at_the_watermark_not_at_zero() {
    let temp = TempDir::new("starts-at-watermark");
    let archive = temp.join("encrypted.zip");
    let dictionary = temp.join("dict.txt");
    let checkpoint_path = temp.join("run.acx-checkpoint");
    write_zip(&archive);
    // The password is at index 0. A checkpoint watermark of 1 must make the
    // resumed run start at index 1, so it cannot find the password.
    write_dictionary(&dictionary, &[PASSWORD, "wrong"]);
    let checkpoint = checkpoint_for(&archive, &dictionary, 2);
    CheckpointStore::new(checkpoint_path.clone())
        .save(&checkpoint)
        .expect("save checkpoint");

    let output = acx()
        .arg("-f")
        .arg(&archive)
        .arg("-d")
        .arg(&dictionary)
        .arg("--checkpoint")
        .arg(&checkpoint_path)
        .arg("--resume")
        .output()
        .expect("run acx");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(1),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("Resume:") && stdout.contains("candidate 1/2"),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("NOT FOUND"), "stdout: {stdout}");
}

#[test]
fn resume_rejects_a_changed_dictionary() {
    let temp = TempDir::new("mismatch");
    let archive = temp.join("encrypted.zip");
    let dictionary = temp.join("dict.txt");
    let checkpoint_path = temp.join("run.acx-checkpoint");
    write_zip(&archive);
    write_dictionary(&dictionary, &["wrong", PASSWORD]);
    let checkpoint = checkpoint_for(&archive, &dictionary, 2);
    CheckpointStore::new(checkpoint_path.clone())
        .save(&checkpoint)
        .expect("save checkpoint");
    write_dictionary(&dictionary, &["changed", PASSWORD, "extra"]);

    let output = acx()
        .arg("-f")
        .arg(&archive)
        .arg("-d")
        .arg(&dictionary)
        .arg("--checkpoint")
        .arg(&checkpoint_path)
        .arg("--resume")
        .output()
        .expect("run acx");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "stderr: {stderr}");
    assert!(
        stderr.contains("dictionary fingerprint"),
        "stderr: {stderr}"
    );
}
