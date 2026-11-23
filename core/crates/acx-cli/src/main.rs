// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

use std::ffi::OsString;
use std::process::ExitCode;

const HELP: &str = r#"ArchCracker command-line interface

Usage:
  acx --version
  acx --help
  acx -f <archive> -m dict -d <dictionary> -t <threads>

M0: the attack pipeline is not implemented yet.
Planned: dictionary, mask, brute force, resume, auto-extract.
"#;

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();

    if args.is_empty() {
        eprintln!("{HELP}");
        return ExitCode::from(2);
    }

    let has = |flag: &str| args.iter().any(|a| a.to_string_lossy() == flag);

    if has("--help") || has("-h") {
        print!("{HELP}");
        return ExitCode::SUCCESS;
    }

    if has("--version") || has("-V") {
        println!("{}", acx_core::version_string());
        return ExitCode::SUCCESS;
    }

    eprintln!("acx: attack pipeline is not implemented in M0 (see docs/roadmap.md)");
    ExitCode::from(2)
}
