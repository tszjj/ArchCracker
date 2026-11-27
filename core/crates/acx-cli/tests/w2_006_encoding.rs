// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

//! End-to-end tests for W2-006 encoding variants, strict mode, and counters.

use acx_core::archive::ArchiveSource;
use acx_core::checkpoint::{
    ArchiveFingerprint, AttackFingerprint, Checkpoint, CheckpointStore, FileFingerprint,
};
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

const HELLO: &[u8] = b"ArchCracker W2-006 encoding fixture";

fn scratch_dir() -> &'static Path {
    static SCRATCH: OnceLock<PathBuf> = OnceLock::new();
    SCRATCH.get_or_init(|| {
        let preferred = std::env::temp_dir();
        let probe = preferred.join(format!("acx-cli-w2-006-probe-{}.tmp", std::process::id()));
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
            "acx-cli-w2-006-{tag}-{}-{nanos}-{id}",
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

fn write_zipcrypto_zip_bytes(path: &Path, password: &[u8]) {
    let file = std::fs::File::create(path)
        .unwrap_or_else(|error| panic!("create {}: {error}", path.display()));
    let mut writer = ZipWriter::new(file);
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .with_deprecated_encryption(password)
        .expect("ZipCrypto file options");
    writer
        .start_file("hello.txt", options)
        .expect("start hello.txt");
    writer.write_all(HELLO).expect("write hello.txt");
    writer.finish().expect("finish encrypted zip");
}

fn write_7z_password(path: &Path, password: &str) {
    let mut writer = ArchiveWriter::create(path).expect("create 7z");
    let mut methods = vec![EncoderConfiguration::new(EncoderMethod::LZMA2)];
    methods.push(AesEncoderOptions::new(Password::from(password)).into());
    writer.set_content_methods(methods);
    writer
        .push_archive_entry(
            ArchiveEntry::new_file("hello.txt"),
            Some(Cursor::new(HELLO.to_vec())),
        )
        .expect("push hello.txt");
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

fn dictionary_checkpoint(archive: &Path, dictionary: &Path, path: &Path) {
    let source = ArchiveSource::resolve(archive).expect("resolve archive");
    let archive_fp = ArchiveFingerprint::from_source(&source).expect("archive fingerprint");
    let dictionary_fp = FileFingerprint::from_path(dictionary).expect("dictionary fingerprint");
    let checkpoint = Checkpoint::new(
        archive_fp,
        Some(dictionary_fp),
        AttackFingerprint::dictionary(),
        1,
        0,
        0,
        1,
    );
    CheckpointStore::new(path.to_path_buf())
        .save(&checkpoint)
        .expect("save checkpoint");
}

#[test]
fn zip_gbk_password_hits_with_auto_variants() {
    let temp = TempDir::new("zip-gbk");
    let zip = temp.join("gbk.zip");
    let dict = temp.join("d.txt");
    let (gbk, _, had_errors) = encoding_rs::GBK.encode("中文密码");
    assert!(!had_errors);
    write_zipcrypto_zip_bytes(&zip, gbk.as_ref());
    write_dictionary(&dict, &["中文密码"]);

    let output = acx()
        .arg("-f")
        .arg(&zip)
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
        Some(0),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(stdout.contains("FOUND: 中文密码"), "stdout: {stdout}");
}

#[test]
fn zip_cp437_password_hits_with_auto_variants() {
    let temp = TempDir::new("zip-cp437");
    let zip = temp.join("cp437.zip");
    let dict = temp.join("d.txt");
    // "café" in CP437: c a f 0x82.
    write_zipcrypto_zip_bytes(&zip, &[b'c', b'a', b'f', 0x82]);
    write_dictionary(&dict, &["café"]);

    let output = acx()
        .arg("-f")
        .arg(&zip)
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
        Some(0),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(stdout.contains("FOUND: café"), "stdout: {stdout}");
}

#[test]
fn zip_utf8_password_still_hits() {
    let temp = TempDir::new("zip-utf8");
    let zip = temp.join("utf8.zip");
    let dict = temp.join("d.txt");
    write_zipcrypto_zip_bytes(&zip, "中文密码".as_bytes());
    write_dictionary(&dict, &["中文密码"]);

    let output = acx()
        .arg("-f")
        .arg(&zip)
        .arg("-d")
        .arg(&dict)
        .output()
        .expect("run acx");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(0), "stdout: {stdout}");
    assert!(stdout.contains("FOUND: 中文密码"), "stdout: {stdout}");
}

#[test]
fn sevenz_utf16_internal_path_hits_with_strict() {
    let temp = TempDir::new("7z-utf16");
    let archive = temp.join("cn.7z");
    let dict = temp.join("d.txt");
    write_7z_password(&archive, "中文密码");
    write_dictionary(&dict, &["wrong", "中文密码"]);

    let output = acx()
        .arg("-f")
        .arg(&archive)
        .arg("-d")
        .arg(&dict)
        .arg("--strict")
        .arg("--report-stats")
        .output()
        .expect("run acx");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(stdout.contains("FOUND: 中文密码"), "stdout: {stdout}");
    assert!(stdout.contains("Stats:"), "stdout: {stdout}");
}

#[test]
fn zip_report_stats_counts_variants() {
    let temp = TempDir::new("stats");
    let zip = temp.join("gbk.zip");
    let dict = temp.join("d.txt");
    let (gbk, _, _) = encoding_rs::GBK.encode("中文密码");
    write_zipcrypto_zip_bytes(&zip, gbk.as_ref());
    write_dictionary(&dict, &["中文密码"]);

    let output = acx()
        .arg("-f")
        .arg(&zip)
        .arg("-d")
        .arg(&dict)
        .arg("--report-stats")
        .output()
        .expect("run acx");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(0), "stdout: {stdout}");
    assert!(
        stdout.contains("Stats: encoding attempts=2"),
        "stdout: {stdout}"
    );
    // W2-007: ZIP now reports its verifier rejects and full attempts instead
    // of an always-zero placeholder. The exact split depends on the ZipCrypto
    // 1/256 check-header collision, so verify the contract, not a fixed value.
    assert!(stdout.contains("zip_verifier="), "stdout: {stdout}");
    assert!(stdout.contains("full attempted="), "stdout: {stdout}");
}

#[test]
fn estimate_reports_variant_multiplier() {
    let temp = TempDir::new("estimate");
    let zip = temp.join("gbk.zip");
    write_zipcrypto_zip_bytes(&zip, b"x");

    let output = acx()
        .arg("-f")
        .arg(&zip)
        .arg("--mask")
        .arg("?d?d")
        .arg("--estimate")
        .output()
        .expect("run acx");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(0), "stdout: {stdout}");
    assert!(
        stdout.contains("Encoding variants: up to 3 per candidate"),
        "stdout: {stdout}"
    );
}

#[test]
fn resume_rejects_strict_or_encoding_option_changes() {
    let temp = TempDir::new("resume-options");
    let zip = temp.join("a.zip");
    let dict = temp.join("d.txt");
    let checkpoint = temp.join("run.acx-checkpoint");
    write_zipcrypto_zip_bytes(&zip, b"x");
    write_dictionary(&dict, &["x"]);
    dictionary_checkpoint(&zip, &dict, &checkpoint);

    let strict = acx()
        .arg("-f")
        .arg(&zip)
        .arg("-d")
        .arg(&dict)
        .arg("--checkpoint")
        .arg(&checkpoint)
        .arg("--resume")
        .arg("--strict")
        .output()
        .expect("run acx");
    let stderr = String::from_utf8_lossy(&strict.stderr);
    assert_eq!(strict.status.code(), Some(2), "stderr: {stderr}");
    assert!(
        stderr.contains("attack signature changed"),
        "stderr: {stderr}"
    );

    let encoding = acx()
        .arg("-f")
        .arg(&zip)
        .arg("-d")
        .arg(&dict)
        .arg("--checkpoint")
        .arg(&checkpoint)
        .arg("--resume")
        .arg("--encoding-variants")
        .arg("gbk")
        .output()
        .expect("run acx");
    let stderr = String::from_utf8_lossy(&encoding.stderr);
    assert_eq!(encoding.status.code(), Some(2), "stderr: {stderr}");
    assert!(
        stderr.contains("attack signature changed"),
        "stderr: {stderr}"
    );

    // Default options still match the default checkpoint.
    let default = acx()
        .arg("-f")
        .arg(&zip)
        .arg("-d")
        .arg(&dict)
        .arg("--checkpoint")
        .arg(&checkpoint)
        .arg("--resume")
        .output()
        .expect("run acx");
    assert_eq!(
        default.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&default.stderr)
    );
}

#[test]
fn explicit_encoding_variant_is_rejected_for_7z() {
    let temp = TempDir::new("7z-variant");
    let archive = temp.join("cn.7z");
    let dict = temp.join("d.txt");
    write_7z_password(&archive, "中文密码");
    write_dictionary(&dict, &["中文密码"]);

    let output = acx()
        .arg("-f")
        .arg(&archive)
        .arg("-d")
        .arg(&dict)
        .arg("--encoding-variants")
        .arg("gbk")
        .output()
        .expect("run acx");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(2), "stderr: {stderr}");
    assert!(stderr.contains("not supported for 7z"), "stderr: {stderr}");
}

#[test]
fn batch_default_does_not_print_stats() {
    let temp = TempDir::new("batch-no-stats");
    let zip = temp.join("gbk.zip");
    let dict = temp.join("d.txt");
    let (gbk, _, _) = encoding_rs::GBK.encode("中文密码");
    write_zipcrypto_zip_bytes(&zip, gbk.as_ref());
    write_dictionary(&dict, &["中文密码"]);
    std::fs::write(
        temp.join("jobs.toml"),
        r#"
[[jobs]]
id = "gbk"
archive = "gbk.zip"
mode = "dict"
dictionary = "d.txt"
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
    assert!(!stdout.contains("[gbk] Stats:"), "stdout: {stdout}");
}

#[test]
fn batch_reuse_prepass_is_not_counted_as_tried_or_stats() {
    let temp = TempDir::new("batch-reuse-stats");
    let zip = temp.join("shared.zip");
    let dict_a = temp.join("a.txt");
    let dict_b = temp.join("b.txt");
    write_zipcrypto_zip_bytes(&zip, b"shared");
    write_dictionary(&dict_a, &["shared"]);
    write_dictionary(&dict_b, &["other"]);
    std::fs::write(
        temp.join("jobs.toml"),
        r#"
max_parallel = 1
reuse_found = true
checkpoint_root = "runs"

[[jobs]]
id = "a"
archive = "shared.zip"
mode = "dict"
dictionary = "a.txt"

[[jobs]]
id = "b"
archive = "shared.zip"
mode = "dict"
dictionary = "b.txt"
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
    assert!(
        stdout.contains("[b] FOUND: shared (reused)"),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("[b] Stats: encoding attempts=0 (candidates=0"),
        "stdout: {stdout}"
    );
    assert!(!stdout.contains("tried 1/1"), "stdout: {stdout}");
}

#[test]
fn batch_manifest_carries_encoding_and_stats_fields() {
    let temp = TempDir::new("batch");
    let zip = temp.join("gbk.zip");
    let dict = temp.join("d.txt");
    let (gbk, _, _) = encoding_rs::GBK.encode("中文密码");
    write_zipcrypto_zip_bytes(&zip, gbk.as_ref());
    write_dictionary(&dict, &["中文密码"]);
    std::fs::write(
        temp.join("jobs.toml"),
        r#"
[[jobs]]
id = "gbk"
archive = "gbk.zip"
mode = "dict"
dictionary = "d.txt"
encoding_variants = "auto"
strict = true
rar_no_fast_reject = true
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
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(stdout.contains("[gbk] FOUND: 中文密码"), "stdout: {stdout}");
    assert!(stdout.contains("[gbk] Stats:"), "stdout: {stdout}");
}
