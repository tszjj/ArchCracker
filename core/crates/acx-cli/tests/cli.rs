// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 ArchCracker contributors

use std::process::Command;

fn acx() -> Command {
    Command::new(env!("CARGO_BIN_EXE_acx"))
}

#[test]
fn version_prints_product_and_version() {
    let out = acx().arg("--version").output().expect("run acx");
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("ArchCracker"), "stdout: {text}");
    assert!(text.contains(env!("CARGO_PKG_VERSION")), "stdout: {text}");
}

#[test]
fn help_prints_usage() {
    let out = acx().arg("--help").output().expect("run acx");
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("Usage:"), "stdout: {text}");
}

#[test]
fn no_args_exits_two() {
    let out = acx().output().expect("run acx");
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn unknown_arg_exits_two() {
    let out = acx().arg("--nope").output().expect("run acx");
    assert_eq!(out.status.code(), Some(2));
}
