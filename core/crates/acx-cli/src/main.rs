// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

//! ArchCracker command-line interface (W1: ZIP + dictionary slice).

use acx_core::archive::{self, ArchiveSessionFactory, Encryption, ZipFactory};
use acx_core::candidates::Dictionary;
use acx_core::scheduler;
use clap::Parser;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

/// Exit code used when the archive is unusable (bad format, unencrypted, AES).
const EXIT_ARCHIVE: u8 = 3;
/// Exit code used for argument and dictionary problems.
const EXIT_USAGE: u8 = 2;
/// Exit code used when no candidate password matched.
const EXIT_NOT_FOUND: u8 = 1;

#[derive(Parser)]
#[command(
    name = "ArchCracker",
    bin_name = "acx",
    version = acx_core::VERSION,
    about = "Offline archive password recovery (authorized use only)",
    long_about = None
)]
struct Cli {
    /// Archive to recover (ZIP).
    #[arg(short = 'f', long = "file", value_name = "PATH")]
    file: PathBuf,

    /// Attack mode; only `dict` is supported in the W1 slice.
    #[arg(
        short = 'm',
        long = "mode",
        value_name = "MODE",
        default_value = "dict"
    )]
    mode: String,

    /// Password dictionary, one candidate per line.
    #[arg(short = 'd', long = "dictionary", value_name = "PATH")]
    dictionary: PathBuf,

    /// Worker threads (clamped to 1..=256 by the scheduler).
    #[arg(short = 't', long = "threads", value_name = "N", default_value_t = 1)]
    threads: usize,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    run(cli)
}

fn run(cli: Cli) -> ExitCode {
    if cli.mode != "dict" {
        eprintln!(
            "acx: unsupported mode `{}`: only `dict` is supported in the W1 slice",
            cli.mode
        );
        return ExitCode::from(EXIT_USAGE);
    }

    let info = match archive::preflight(&cli.file) {
        Ok(info) => info,
        Err(error) => {
            eprintln!("acx: {error}");
            return ExitCode::from(EXIT_ARCHIVE);
        }
    };

    println!("Archive: {}", info.path.display());
    println!("Format: {}", info.format.as_str());
    println!("Encryption: {}", info.encryption.as_str());
    println!("Entries: {}", info.entries.len());
    match info.selected_entry() {
        Some(entry) => println!(
            "Selected: {} ({} bytes)",
            entry.name, entry.uncompressed_size
        ),
        None => println!("Selected: none"),
    }

    if info.selected.is_none() {
        eprintln!("acx: archive is not encrypted or has no file entries");
        return ExitCode::from(EXIT_ARCHIVE);
    }

    if info.encryption == Encryption::Aes {
        eprintln!("acx: AES is not supported in the W1 slice");
        return ExitCode::from(EXIT_ARCHIVE);
    }

    let dictionary = match Dictionary::load(&cli.dictionary) {
        Ok(dictionary) => dictionary,
        Err(error) => {
            eprintln!("acx: {error}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    println!("Passwords: {}", dictionary.len());
    if dictionary.is_empty() {
        eprintln!("acx: dictionary is empty");
        return ExitCode::from(EXIT_USAGE);
    }

    let factory: Arc<dyn ArchiveSessionFactory> = Arc::new(ZipFactory {
        path: cli.file.clone(),
    });
    let passwords = Arc::new(dictionary.entries().to_vec());

    match scheduler::run(factory, passwords, cli.threads) {
        Ok(Some(hit)) => {
            let password = String::from_utf8_lossy(&hit.password);
            println!("FOUND: {password}");
            ExitCode::SUCCESS
        }
        Ok(None) => {
            println!("NOT FOUND");
            ExitCode::from(EXIT_NOT_FOUND)
        }
        Err(error) => {
            eprintln!("acx: {error}");
            ExitCode::from(EXIT_ARCHIVE)
        }
    }
}
