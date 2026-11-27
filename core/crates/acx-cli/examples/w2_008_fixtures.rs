// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

//! Generate the W2-008 fixture set. Output is written to a local, gitignored
//! directory only; no archive or dictionary is ever committed.
//!
//! Usage: cargo run -p acx-cli --example w2_008_fixtures -- <out_dir> [password]

#[path = "../tests/common/w2_008_fixtures.rs"]
mod fixtures;

use std::path::{Path, PathBuf};
use std::process::Command;

fn find_tool(env_name: &str, fallback: &str) -> Option<PathBuf> {
    if let Ok(value) = std::env::var(env_name) {
        let path = PathBuf::from(value);
        if path.is_file() {
            return Some(path);
        }
    }
    let path = PathBuf::from(fallback);
    path.is_file().then_some(path)
}

fn run(tool: &Path, current_dir: &Path, args: &[&str]) -> bool {
    let output = Command::new(tool)
        .current_dir(current_dir)
        .args(args)
        .output();
    match output {
        Ok(result) if result.status.success() => true,
        Ok(result) => {
            eprintln!(
                "tool {} failed: {}",
                tool.display(),
                String::from_utf8_lossy(&result.stderr)
            );
            false
        }
        Err(error) => {
            eprintln!("tool {} failed: {error}", tool.display());
            false
        }
    }
}

fn main() {
    let mut args = std::env::args().skip(1);
    let out = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("tests/corpus/out/fixtures"));
    let password = args.next().unwrap_or_else(|| "P@ssw0rd123".to_string());

    std::fs::create_dir_all(&out).expect("create fixture output directory");
    let out = std::fs::canonicalize(&out).expect("canonicalize fixture output directory");
    fixtures::write_zipcrypto(&out.join("zipcrypto.zip"), password.as_bytes());
    fixtures::write_aes_zip(&out.join("aes.zip"), &password);
    fixtures::write_plain_zip(&out.join("plain.zip"));
    fixtures::write_7z_password(&out.join("aes.7z"), &password);

    let truncated = out.join("truncated.zip");
    std::fs::copy(out.join("aes.zip"), &truncated).expect("copy AES fixture");
    fixtures::truncate(&truncated, 64);

    let corrupted = out.join("corrupted.zip");
    std::fs::copy(out.join("aes.zip"), &corrupted).expect("copy AES fixture");
    fixtures::flip_byte(&corrupted, 80);

    let work = out.join("work");
    std::fs::create_dir_all(&work).expect("create tool work directory");
    std::fs::write(work.join("hello.txt"), fixtures::HELLO).expect("write plaintext");

    if let Some(tool) = find_tool("ACX_7Z", r"C:\Program Files\7-Zip\7z.exe") {
        let archive = out.join("header_aes.7z");
        let password_arg = format!("-p{password}");
        if !run(
            &tool,
            &work,
            &[
                "a",
                "-t7z",
                "-mhe=on",
                &password_arg,
                archive.to_str().expect("archive path"),
                "hello.txt",
            ],
        ) {
            eprintln!("skipping 7z header-encrypted fixture");
        }
    } else {
        eprintln!("7-Zip not found; skipping header-encrypted fixture");
    }

    if let Some(unrar) = find_tool("ACX_UNRAR", r"C:\Program Files\WinRAR\UnRAR.exe") {
        if let Some(rar) = unrar.parent().map(|parent| parent.join("Rar.exe")) {
            if rar.is_file() {
                let password_arg = format!("-p{password}");
                for (name, mode) in [("rar5.rar", "-ma5"), ("rar4.rar", "-ma4")] {
                    let archive = out.join(name);
                    if !run(
                        &rar,
                        &work,
                        &[
                            "a",
                            "-idq",
                            "-y",
                            mode,
                            &password_arg,
                            archive.to_str().expect("archive path"),
                            "hello.txt",
                        ],
                    ) {
                        eprintln!("skipping {name} fixture");
                    }
                }
            }
        }
    } else {
        eprintln!("UnRAR not found; skipping RAR fixtures");
    }

    let _ = std::fs::remove_dir_all(&work);
    println!("W2-008 fixtures written to {}", out.display());
}
