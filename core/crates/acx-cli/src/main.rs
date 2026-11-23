// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 ArchCracker contributors

use std::process::ExitCode;

fn print_help() {
    println!(
        "{}\n\
         \n\
         Usage:\n\
           acx --version\n\
           acx --help\n\
         \n\
         M0: the attack pipeline is not implemented yet.\n\
         Planned: -f <archive> -m dict -d <dict> -t <threads>",
        acx_core::version_string()
    );
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        return ExitCode::SUCCESS;
    }

    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("{}", acx_core::version_string());
        return ExitCode::SUCCESS;
    }

    eprintln!("acx: attack pipeline is not implemented in M0 (see docs/roadmap.md)");
    ExitCode::from(2)
}
