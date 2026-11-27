// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

//! W2-008 differential harness: compares `acx` results against external
//! 7-Zip / UnRAR oracles and asserts W2-007 counter invariants. Fixtures are
//! generated at runtime; no binary is committed.

#[path = "common/w2_008_fixtures.rs"]
mod fixtures;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const PASSWORD: &str = "P@ssw0rd123";
const UNICODE_PASSWORD: &str = "中文密码";

fn acx() -> Command {
    Command::new(env!("CARGO_BIN_EXE_acx"))
}

fn tool_from_env_or(env_name: &str, fallback: &str) -> Option<PathBuf> {
    if let Ok(value) = std::env::var(env_name) {
        let path = PathBuf::from(value);
        if path.is_file() {
            return Some(path);
        }
    }
    let path = PathBuf::from(fallback);
    path.is_file().then_some(path)
}

fn oracle_7z(tool: &Path, archive: &Path, password: &str) -> bool {
    let password_arg = format!("-p{password}");
    Command::new(tool)
        .args(["t", "-bso0", "-bsp0", &password_arg])
        .arg(archive)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn oracle_unrar(tool: &Path, archive: &Path, password: &str) -> bool {
    let password_arg = format!("-p{password}");
    Command::new(tool)
        .args(["t", &password_arg])
        .arg(archive)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn write_dictionary(path: &Path, lines: &[&str]) {
    let mut body = lines.join("\n");
    body.push('\n');
    std::fs::write(path, body).expect("write dictionary");
}

fn run_with_dictionary(archive: &Path, dictionary: &Path, extra: &[&str]) -> Output {
    let mut command = acx();
    command.arg("-f").arg(archive).arg("-d").arg(dictionary);
    command.args(["-t", "2", "--report-stats"]);
    command.args(extra);
    command.output().expect("run acx")
}

fn stdout_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stat_value(stdout: &str, key: &str) -> u64 {
    let marker = format!("{key}=");
    let rest = stdout
        .split_once(&marker)
        .unwrap_or_else(|| panic!("missing `{key}` in stats: {stdout}"))
        .1;
    rest.chars()
        .take_while(|character| character.is_ascii_digit())
        .collect::<String>()
        .parse()
        .unwrap_or_else(|_| panic!("invalid `{key}` in stats: {stdout}"))
}

fn assert_counter_invariants(stdout: &str) {
    let attempts = stat_value(stdout, "encoding attempts");
    let fast = stat_value(stdout, "fast rejects");
    let full = stat_value(stdout, "full attempted");
    let external = stat_value(stdout, "external attempts");
    assert_eq!(attempts, fast + full, "counter equation: {stdout}");
    assert!(
        external <= full,
        "external attempts must be a subset: {stdout}"
    );
}

fn temp_dir(tag: &str) -> PathBuf {
    let name = format!(
        "acx-w2-008-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or(0)
    );
    let preferred = std::env::temp_dir().join(&name);
    if std::fs::create_dir_all(&preferred).is_ok() {
        return preferred;
    }
    let mut fallback = std::env::current_exe().unwrap_or_default();
    fallback.pop();
    fallback.pop();
    fallback.push("acx-test-tmp");
    fallback.push(name);
    std::fs::create_dir_all(&fallback).expect("create fallback temp dir");
    fallback
}

#[test]
fn zipcrypto_matches_7z_oracle_and_counter_equation() {
    let Some(tool) = tool_from_env_or("ACX_7Z", r"C:\Program Files\7-Zip\7z.exe") else {
        eprintln!("skipping ZIP oracle check: 7-Zip not found");
        return;
    };
    let dir = temp_dir("zipcrypto");
    let archive = dir.join("zipcrypto.zip");
    let dictionary = dir.join("dict.txt");
    fixtures::write_zipcrypto(&archive, PASSWORD.as_bytes());
    write_dictionary(&dictionary, &["wrong-one", PASSWORD]);

    let output = run_with_dictionary(&archive, &dictionary, &[]);
    let stdout = stdout_text(&output);
    assert!(output.status.success(), "acx failed: {stdout}");
    assert!(stdout.contains("FOUND:"), "no hit: {stdout}");
    assert!(
        oracle_7z(&tool, &archive, PASSWORD),
        "oracle rejected correct password"
    );
    assert!(
        !oracle_7z(&tool, &archive, "wrong-one"),
        "oracle accepted wrong password"
    );
    assert_counter_invariants(&stdout);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn aes_zip_reports_verifier_bucket() {
    let dir = temp_dir("aes-zip");
    let archive = dir.join("aes.zip");
    let dictionary = dir.join("dict.txt");
    fixtures::write_aes_zip(&archive, PASSWORD);
    write_dictionary(&dictionary, &["wrong-one", PASSWORD]);

    let output = run_with_dictionary(&archive, &dictionary, &[]);
    let stdout = stdout_text(&output);
    assert!(output.status.success(), "acx failed: {stdout}");
    assert!(stdout.contains("FOUND:"), "no hit: {stdout}");
    assert!(
        stdout.contains("zip_verifier="),
        "per-filter bucket missing: {stdout}"
    );
    assert_counter_invariants(&stdout);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn sevenz_default_and_strict_both_match_known_password() {
    let dir = temp_dir("sevenz");
    let archive = dir.join("aes.7z");
    let dictionary = dir.join("dict.txt");
    fixtures::write_7z_password(&archive, UNICODE_PASSWORD);
    write_dictionary(&dictionary, &["wrong-one", UNICODE_PASSWORD]);

    for extra in [&[][..], &["--strict"][..]] {
        let output = run_with_dictionary(&archive, &dictionary, extra);
        let stdout = stdout_text(&output);
        assert!(output.status.success(), "acx failed: {stdout}");
        assert!(stdout.contains("FOUND:"), "no hit with {extra:?}: {stdout}");
        assert_counter_invariants(&stdout);
        if extra.first() == Some(&"--strict") {
            assert_eq!(
                stat_value(&stdout, "sevenz_first_block"),
                0,
                "strict must disable the probe: {stdout}"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rar5_matches_unrar_oracle_and_counts_external_calls() {
    let Some(unrar) = tool_from_env_or("ACX_UNRAR", r"C:\Program Files\WinRAR\UnRAR.exe") else {
        eprintln!("skipping RAR oracle check: UnRAR not found");
        return;
    };
    let Some(rar) = unrar.parent().map(|parent| parent.join("Rar.exe")) else {
        return;
    };
    if !rar.is_file() {
        eprintln!("skipping RAR oracle check: Rar.exe not found beside UnRAR");
        return;
    }
    let dir = temp_dir("rar5");
    let work = dir.join("work");
    std::fs::create_dir_all(&work).expect("create work dir");
    std::fs::write(work.join("hello.txt"), fixtures::HELLO).expect("write plaintext");
    let archive = dir.join("rar5.rar");
    let dictionary = dir.join("dict.txt");
    let password_arg = format!("-p{PASSWORD}");
    let created = Command::new(&rar)
        .current_dir(&work)
        .args([
            "a",
            "-idq",
            "-y",
            "-ma5",
            &password_arg,
            archive.to_str().expect("archive path"),
            "hello.txt",
        ])
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false);
    if !created {
        eprintln!("skipping RAR oracle check: fixture creation failed");
        return;
    }
    write_dictionary(&dictionary, &["wrong-one", PASSWORD]);

    let output = run_with_dictionary(&archive, &dictionary, &[]);
    let stdout = stdout_text(&output);
    assert!(output.status.success(), "acx failed: {stdout}");
    assert!(stdout.contains("FOUND:"), "no hit: {stdout}");
    assert!(
        oracle_unrar(&unrar, &archive, PASSWORD),
        "oracle rejected correct password"
    );
    assert!(
        !oracle_unrar(&unrar, &archive, "wrong-one"),
        "oracle accepted wrong password"
    );
    assert!(
        stat_value(&stdout, "external attempts") >= 1,
        "external call not counted: {stdout}"
    );
    assert_counter_invariants(&stdout);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn truncated_zip_is_an_archive_error_not_a_miss() {
    let dir = temp_dir("truncated");
    let archive = dir.join("truncated.zip");
    let dictionary = dir.join("dict.txt");
    fixtures::write_aes_zip(&archive, PASSWORD);
    fixtures::truncate(&archive, 64);
    write_dictionary(&dictionary, &[PASSWORD]);

    let output = run_with_dictionary(&archive, &dictionary, &[]);
    let stdout = stdout_text(&output);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.code() == Some(3) || stderr.contains("error") || stdout.contains("error"),
        "truncated archive should be classified as an error: stdout={stdout} stderr={stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
