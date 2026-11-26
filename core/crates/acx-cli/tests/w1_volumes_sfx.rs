// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

//! End-to-end tests for W1-005 split volumes and SFX payload offsets.

use sevenz_rust2::encoder_options::AesEncoderOptions;
use sevenz_rust2::{ArchiveEntry, ArchiveWriter, EncoderConfiguration, EncoderMethod, Password};
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use zip::unstable::write::FileOptionsExt;
use zip::write::SimpleFileOptions;
use zip::{AesMode, CompressionMethod, ZipWriter};

const PASSWORD: &str = "P@ssw0rd123";
const HELLO: &[u8] = b"ArchCracker W1-005 split/SFX fixture";

fn scratch_dir() -> &'static Path {
    static SCRATCH: OnceLock<PathBuf> = OnceLock::new();
    SCRATCH.get_or_init(|| {
        let preferred = std::env::temp_dir();
        let probe = preferred.join(format!("acx-cli-w1-005-probe-{}.tmp", std::process::id()));
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
            "acx-cli-w1-005-{tag}-{}-{nanos}-{id}",
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

fn write_dictionary(path: &Path, lines: &[&str]) {
    let mut contents = lines.join("\n");
    contents.push('\n');
    std::fs::write(path, contents).expect("write dictionary");
}

fn acx() -> Command {
    Command::new(env!("CARGO_BIN_EXE_acx"))
}

fn write_zipcrypto(path: &Path) {
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

fn write_aes_zip(path: &Path) {
    let file = std::fs::File::create(path).expect("create zip");
    let mut writer = ZipWriter::new(file);
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .with_aes_encryption(AesMode::Aes256, PASSWORD);
    writer.start_file("hello.txt", options).expect("start");
    writer.write_all(HELLO).expect("write");
    writer.finish().expect("finish");
}

fn write_7z(path: &Path) {
    let mut writer = ArchiveWriter::create(path).expect("create 7z");
    writer.set_encrypt_header(false);
    writer.set_content_methods(vec![
        EncoderConfiguration::new(EncoderMethod::LZMA2),
        AesEncoderOptions::new(Password::from(PASSWORD)).into(),
    ]);
    writer
        .push_archive_entry(
            ArchiveEntry::new_file("hello.txt"),
            Some(Cursor::new(HELLO.to_vec())),
        )
        .expect("push");
    writer.finish().expect("finish 7z");
}

/// Split `source` into `base.001`, `base.002`, ... and return the first part.
fn split_file(source: &Path, base: &Path, parts: usize) -> PathBuf {
    let bytes = std::fs::read(source).expect("read source");
    let chunk = bytes.len().div_ceil(parts).max(1);
    let mut first = None;
    for index in 0..parts {
        let start = index * chunk;
        if start >= bytes.len() {
            break;
        }
        let end = (start + chunk).min(bytes.len());
        let part = PathBuf::from(format!("{}.{:03}", base.display(), index + 1));
        std::fs::write(&part, &bytes[start..end]).expect("write part");
        first.get_or_insert_with(|| part.clone());
    }
    first.expect("at least one part")
}

fn prepend_mz_stub(source: &Path, destination: &Path) {
    let payload = std::fs::read(source).expect("read payload");
    let mut stub = vec![b'M', b'Z'];
    stub.extend(std::iter::repeat_n(b'A', 512));
    stub.extend_from_slice(&payload);
    std::fs::write(destination, stub).expect("write SFX");
}

fn run_hit(archive: &Path, dictionary: &Path) -> String {
    let output = acx()
        .arg("-f")
        .arg(archive)
        .arg("-m")
        .arg("dict")
        .arg("-d")
        .arg(dictionary)
        .arg("-t")
        .arg("2")
        .output()
        .expect("run acx");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "exit {:?}\nstdout: {stdout}\nstderr: {stderr}",
        output.status.code()
    );
    assert!(stdout.contains("FOUND:"), "stdout: {stdout}");
    stdout
}

#[test]
fn split_zipcrypto_zip_is_found() {
    let temp = TempDir::new("split-zip");
    let whole = temp.join("whole.zip");
    write_zipcrypto(&whole);
    let first = split_file(&whole, &temp.join("movie.zip"), 2);
    let dict = temp.join("dict.txt");
    write_dictionary(&dict, &["wrong", PASSWORD]);
    run_hit(&first, &dict);
}

#[test]
fn split_aes_zip_is_found() {
    let temp = TempDir::new("split-aes");
    let whole = temp.join("whole.zip");
    write_aes_zip(&whole);
    let first = split_file(&whole, &temp.join("movie.zip"), 2);
    let dict = temp.join("dict.txt");
    write_dictionary(&dict, &["wrong", PASSWORD]);
    let stdout = run_hit(&first, &dict);
    assert!(stdout.contains("Encryption: aes"), "{stdout}");
}

#[test]
fn single_zip_named_001_is_not_missing() {
    let temp = TempDir::new("single-001");
    let archive = temp.join("single.zip.001");
    write_zipcrypto(&archive);
    let dict = temp.join("dict.txt");
    write_dictionary(&dict, &[PASSWORD]);
    run_hit(&archive, &dict);
}

#[test]
fn continuation_zip_path_resolves_to_first_part() {
    let temp = TempDir::new("continuation-zip");
    let whole = temp.join("whole.zip");
    write_aes_zip(&whole);
    split_file(&whole, &temp.join("movie.zip"), 2);
    let second = temp.join("movie.zip.002");
    let dict = temp.join("dict.txt");
    write_dictionary(&dict, &[PASSWORD]);
    run_hit(&second, &dict);
}

#[test]
fn continuation_7z_path_resolves_to_first_part() {
    let temp = TempDir::new("continuation-7z");
    let whole = temp.join("whole.7z");
    write_7z(&whole);
    split_file(&whole, &temp.join("movie.7z"), 2);
    let second = temp.join("movie.7z.002");
    let dict = temp.join("dict.txt");
    write_dictionary(&dict, &[PASSWORD]);
    run_hit(&second, &dict);
}

#[test]
fn complete_archive_with_numeric_extension_is_not_a_volume() {
    let temp = TempDir::new("year-extension");
    let archive = temp.join("movie.2024");
    write_zipcrypto(&archive);
    let dict = temp.join("dict.txt");
    write_dictionary(&dict, &[PASSWORD]);
    run_hit(&archive, &dict);
}

#[test]
fn single_7z_named_001_is_not_missing() {
    let temp = TempDir::new("single-7z-001");
    let archive = temp.join("single.7z.001");
    write_7z(&archive);
    let dict = temp.join("dict.txt");
    write_dictionary(&dict, &[PASSWORD]);
    run_hit(&archive, &dict);
}

#[test]
fn missing_zip_volume_exits_three() {
    let temp = TempDir::new("missing-zip");
    let whole = temp.join("whole.zip");
    write_aes_zip(&whole);
    let first = split_file(&whole, &temp.join("movie.zip"), 2);
    std::fs::remove_file(format!("{}.002", temp.join("movie.zip").display())).expect("remove 002");
    let dict = temp.join("dict.txt");
    write_dictionary(&dict, &[PASSWORD]);

    let output = acx()
        .arg("-f")
        .arg(&first)
        .arg("-d")
        .arg(&dict)
        .output()
        .expect("run acx");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(3), "stderr: {stderr}");
    assert!(
        stderr.contains("missing archive volume"),
        "stderr: {stderr}"
    );
    assert!(stderr.contains("002"), "stderr: {stderr}");
}

#[test]
fn split_7z_is_found() {
    let temp = TempDir::new("split-7z");
    let whole = temp.join("whole.7z");
    write_7z(&whole);
    let first = split_file(&whole, &temp.join("movie.7z"), 2);
    let dict = temp.join("dict.txt");
    write_dictionary(&dict, &["wrong", PASSWORD]);
    run_hit(&first, &dict);
}

#[test]
fn missing_7z_volume_exits_three() {
    let temp = TempDir::new("missing-7z");
    let whole = temp.join("whole.7z");
    write_7z(&whole);
    let first = split_file(&whole, &temp.join("movie.7z"), 2);
    std::fs::remove_file(format!("{}.002", temp.join("movie.7z").display())).expect("remove 002");
    let dict = temp.join("dict.txt");
    write_dictionary(&dict, &[PASSWORD]);

    let output = acx()
        .arg("-f")
        .arg(&first)
        .arg("-d")
        .arg(&dict)
        .output()
        .expect("run acx");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(3), "stderr: {stderr}");
    assert!(
        stderr.contains("missing archive volume"),
        "stderr: {stderr}"
    );
    assert!(stderr.contains("002"), "stderr: {stderr}");
}

#[test]
fn sevenz_sfx_is_found() {
    let temp = TempDir::new("sfx-7z");
    let whole = temp.join("whole.7z");
    write_7z(&whole);
    let sfx = temp.join("archive.exe");
    prepend_mz_stub(&whole, &sfx);
    let dict = temp.join("dict.txt");
    write_dictionary(&dict, &["wrong", PASSWORD]);
    run_hit(&sfx, &dict);
}

#[test]
fn zip_sfx_is_found() {
    let temp = TempDir::new("sfx-zip");
    let whole = temp.join("whole.zip");
    write_aes_zip(&whole);
    let sfx = temp.join("archive.exe");
    prepend_mz_stub(&whole, &sfx);
    let dict = temp.join("dict.txt");
    write_dictionary(&dict, &["wrong", PASSWORD]);
    run_hit(&sfx, &dict);
}

#[test]
fn pkzip_spanned_archive_is_rejected_clearly() {
    let temp = TempDir::new("z01");
    let z01 = temp.join("archive.z01");
    write_aes_zip(&z01);
    let dict = temp.join("dict.txt");
    write_dictionary(&dict, &[PASSWORD]);

    let output = acx()
        .arg("-f")
        .arg(&z01)
        .arg("-d")
        .arg(&dict)
        .output()
        .expect("run acx");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(3), "stderr: {stderr}");
    assert!(stderr.contains("PKZIP spanned"), "stderr: {stderr}");
}
