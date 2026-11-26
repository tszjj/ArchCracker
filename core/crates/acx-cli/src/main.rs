// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

//! ArchCracker command-line interface (W1: ZIP, 7z, and external RAR).

use acx_core::archive::{
    self, ArchiveFormat, ArchiveSessionFactory, ArchiveSource, RarFactory, SevenZFactory,
    ZipFactory,
};
use acx_core::candidates::{BruteSet, CandidateSource, DictionaryStream, HybridSet, MaskSet};
use acx_core::checkpoint::{
    ArchiveFingerprint, AttackFingerprint, Checkpoint, CheckpointStore, FileFingerprint,
};
use acx_core::error::AcxError;
use acx_core::scheduler::{self, RunContext, RunControl, RunOutcome};
use clap::Parser;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// Exit code used when the archive is unusable (bad format, unencrypted, unsupported).
const EXIT_ARCHIVE: u8 = 3;
/// Exit code used for argument and dictionary problems.
const EXIT_USAGE: u8 = 2;
/// Exit code used when no candidate password matched.
const EXIT_NOT_FOUND: u8 = 1;
/// Exit code used when the run stopped with a checkpoint.
const EXIT_STOPPED: u8 = 4;

#[derive(Parser)]
#[command(
    name = "ArchCracker",
    bin_name = "acx",
    version = acx_core::VERSION,
    about = "Offline archive password recovery (authorized use only)",
    long_about = None
)]
struct Cli {
    /// Archive to recover (ZIP, 7z, or RAR via a user-installed UnRAR).
    #[arg(short = 'f', long = "file", value_name = "PATH")]
    file: PathBuf,

    /// Attack mode: `dict`, `mask`, `brute`, or `hybrid`; the flags imply their mode.
    #[arg(
        short = 'm',
        long = "mode",
        value_name = "MODE",
        default_value = "dict"
    )]
    mode: String,

    /// Password dictionary, one candidate per line. Required in dict/hybrid mode.
    #[arg(short = 'd', long = "dictionary", value_name = "PATH")]
    dictionary: Option<PathBuf>,

    /// Fixed-length mask expression; repeat for multiple masks.
    #[arg(long = "mask", value_name = "EXPR", action = clap::ArgAction::Append)]
    mask: Vec<String>,

    /// Rule chain for hybrid mode, e.g. `capitalize|append:123`; repeatable.
    #[arg(long = "rule", value_name = "CHAIN", action = clap::ArgAction::Append)]
    rules: Vec<String>,

    /// Prefix mask for hybrid mode (same syntax as `--mask`).
    #[arg(long = "prefix-mask", value_name = "EXPR")]
    prefix_mask: Option<String>,

    /// Suffix mask for hybrid mode (same syntax as `--mask`).
    #[arg(long = "suffix-mask", value_name = "EXPR")]
    suffix_mask: Option<String>,

    /// Brute-force charset expression (e.g. `?l?d`); literals join the charset.
    /// Requires `--min-len` and `--max-len`.
    #[arg(long = "brute", value_name = "CHARSET")]
    brute: Option<String>,

    /// Minimum brute-force length (>= 1).
    #[arg(long = "min-len", value_name = "N")]
    min_len: Option<usize>,

    /// Maximum brute-force length (<= 128).
    #[arg(long = "max-len", value_name = "N")]
    max_len: Option<usize>,

    /// Custom charset for ?1 (built-in tokens/literals, expanded and deduped).
    #[arg(long = "custom-charset1", value_name = "SET")]
    custom_charset1: Option<String>,

    /// Custom charset for ?2.
    #[arg(long = "custom-charset2", value_name = "SET")]
    custom_charset2: Option<String>,

    /// Custom charset for ?3.
    #[arg(long = "custom-charset3", value_name = "SET")]
    custom_charset3: Option<String>,

    /// Custom charset for ?4.
    #[arg(long = "custom-charset4", value_name = "SET")]
    custom_charset4: Option<String>,

    /// Print keyspace/ETA/space estimates without starting an attack.
    #[arg(long = "estimate")]
    estimate: bool,

    /// Worker threads (clamped to 1..=256 by the scheduler).
    #[arg(short = 't', long = "threads", value_name = "N", default_value_t = 1)]
    threads: usize,

    /// Checkpoint path; defaults to `<archive>.acx-checkpoint`.
    #[arg(long = "checkpoint", value_name = "PATH")]
    checkpoint: Option<PathBuf>,

    /// Resume from an existing checkpoint instead of starting at candidate 0.
    #[arg(long = "resume")]
    resume: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    run(cli)
}

fn run(cli: Cli) -> ExitCode {
    let use_mask = !cli.mask.is_empty() || cli.mode == "mask";
    let use_brute = cli.brute.is_some() || cli.mode == "brute";
    let use_hybrid = !cli.rules.is_empty()
        || cli.prefix_mask.is_some()
        || cli.suffix_mask.is_some()
        || cli.mode == "hybrid";
    if !matches!(cli.mode.as_str(), "dict" | "mask" | "brute" | "hybrid") {
        eprintln!(
            "acx: unsupported mode `{}` (expected dict, mask, brute, or hybrid)",
            cli.mode
        );
        return ExitCode::from(EXIT_USAGE);
    }
    let modes = [use_mask, use_brute, use_hybrid]
        .iter()
        .filter(|active| **active)
        .count();
    if modes > 1 {
        eprintln!(
            "acx: --mask, --brute, and --rule/--prefix-mask/--suffix-mask are mutually exclusive"
        );
        return ExitCode::from(EXIT_USAGE);
    }
    if use_brute {
        if cli.dictionary.is_some() {
            eprintln!("acx: --dictionary and --brute are mutually exclusive");
            return ExitCode::from(EXIT_USAGE);
        }
        if cli.brute.is_none() {
            eprintln!("acx: brute mode requires --brute");
            return ExitCode::from(EXIT_USAGE);
        }
        if cli.min_len.is_none() || cli.max_len.is_none() {
            eprintln!("acx: brute mode requires --min-len and --max-len");
            return ExitCode::from(EXIT_USAGE);
        }
    } else if use_hybrid {
        if cli.dictionary.is_none() {
            eprintln!("acx: hybrid mode requires --dictionary");
            return ExitCode::from(EXIT_USAGE);
        }
        if cli.rules.is_empty() && cli.prefix_mask.is_none() && cli.suffix_mask.is_none() {
            eprintln!(
                "acx: hybrid mode requires --rule, --prefix-mask, or --suffix-mask; use -m dict for a plain dictionary attack"
            );
            return ExitCode::from(EXIT_USAGE);
        }
    } else if use_mask {
        if cli.dictionary.is_some() {
            eprintln!("acx: --dictionary and --mask are mutually exclusive");
            return ExitCode::from(EXIT_USAGE);
        }
        if cli.mask.is_empty() {
            eprintln!("acx: mask mode requires at least one --mask");
            return ExitCode::from(EXIT_USAGE);
        }
    } else if cli.dictionary.is_none() {
        eprintln!("acx: dict mode requires --dictionary");
        return ExitCode::from(EXIT_USAGE);
    }
    if (cli.min_len.is_some() || cli.max_len.is_some()) && !use_brute {
        eprintln!("acx: --min-len/--max-len require --brute");
        return ExitCode::from(EXIT_USAGE);
    }
    if cli.estimate && !(use_mask || use_brute || use_hybrid) {
        eprintln!("acx: --estimate requires --mask, --brute, or hybrid mode");
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
    if info.header_encrypted {
        println!("Entries: n/a (encrypted header)");
    } else if info.whole_archive || matches!(info.format, ArchiveFormat::Rar4 | ArchiveFormat::Rar5)
    {
        println!("Entries: n/a (external RAR engine)");
    } else {
        println!("Entries: {}", info.entries.len());
    }
    if info.header_encrypted {
        println!("Selected: first encrypted entry after the password is known");
    } else if info.whole_archive {
        println!("Selected: whole archive (external RAR test)");
    } else {
        match info.selected_entry() {
            Some(entry) => println!(
                "Selected: {} ({} bytes)",
                entry.name, entry.uncompressed_size
            ),
            None => println!("Selected: none"),
        }
    }

    if cli.estimate {
        return estimate_attack(&cli, &info, use_brute, use_hybrid);
    }

    if !info.has_verification_target() {
        eprintln!("acx: archive is not encrypted or has no file entries");
        return ExitCode::from(EXIT_ARCHIVE);
    }

    let factory: Arc<dyn ArchiveSessionFactory> = match info.format {
        ArchiveFormat::Zip => Arc::new(ZipFactory {
            path: cli.file.clone(),
        }),
        ArchiveFormat::SevenZ => match SevenZFactory::from_info(cli.file.clone(), info.clone()) {
            Ok(factory) => Arc::new(factory),
            Err(error) => {
                eprintln!("acx: {error}");
                return ExitCode::from(EXIT_ARCHIVE);
            }
        },
        ArchiveFormat::Rar4 | ArchiveFormat::Rar5 => {
            match RarFactory::from_info(cli.file.clone(), info.clone()) {
                Ok(factory) => Arc::new(factory),
                Err(error) => {
                    eprintln!("acx: {error}");
                    return ExitCode::from(EXIT_ARCHIVE);
                }
            }
        }
    };
    let checkpoint_path = cli
        .checkpoint
        .clone()
        .unwrap_or_else(|| default_checkpoint_path(&cli.file));
    let source = match ArchiveSource::resolve(&cli.file) {
        Ok(source) => source,
        Err(error) => {
            eprintln!("acx: {error}");
            return ExitCode::from(EXIT_ARCHIVE);
        }
    };
    let archive_fingerprint = match ArchiveFingerprint::from_source(&source) {
        Ok(fingerprint) => fingerprint,
        Err(error) => {
            eprintln!("acx: {error}");
            return ExitCode::from(EXIT_ARCHIVE);
        }
    };

    let store = CheckpointStore::new(checkpoint_path.clone());
    if cli.resume {
        if let Err(error) = store.clear_lock() {
            eprintln!("acx: could not clear stale checkpoint lock: {error}");
            return ExitCode::from(EXIT_USAGE);
        }
    }
    let _lock = match store.lock() {
        Ok(lock) => lock,
        Err(error) => {
            eprintln!("acx: {error}");
            return ExitCode::from(EXIT_USAGE);
        }
    };

    let mut start_index = 0usize;
    let mut tried = 0u64;
    let mut loaded_checkpoint = None;
    if cli.resume {
        let checkpoint = match store.load() {
            Ok(checkpoint) => checkpoint,
            Err(error) => {
                eprintln!("acx: {error}");
                return ExitCode::from(EXIT_USAGE);
            }
        };
        start_index = match usize::try_from(checkpoint.completed_through) {
            Ok(start) => start,
            Err(_) => {
                eprintln!("acx: checkpoint watermark is too large");
                return ExitCode::from(EXIT_USAGE);
            }
        };
        tried = checkpoint.tried;
        loaded_checkpoint = Some(checkpoint);
    }

    let custom_texts = custom_texts(&cli);
    let (dictionary_fingerprint, attack, source, total, label) = if use_brute {
        let charset_text = cli.brute.as_deref().expect("validated --brute");
        let min_len = cli.min_len.expect("validated --min-len");
        let max_len = cli.max_len.expect("validated --max-len");
        let set = match BruteSet::parse(charset_text, &custom_texts, min_len, max_len) {
            Ok(set) => set,
            Err(error) => {
                eprintln!("acx: {error}");
                return ExitCode::from(EXIT_USAGE);
            }
        };
        let estimate = set.estimate(cli.threads);
        for warning in &estimate.warnings {
            eprintln!("WARNING: {warning}");
        }
        let (rate, rate_label) = rate_for(info.format);
        let seconds = estimate.keyspace as f64 / rate;
        if seconds > 86_400.0 {
            eprintln!(
                "WARNING: estimated {} exceeds 24h on {rate_label} at the measured rate",
                format_duration(seconds)
            );
        }
        println!("Brute charset: {charset_text}");
        println!("Lengths: {min_len}..={max_len}");
        println!("Brute keyspace: {}", estimate.keyspace);
        print_space(&estimate.space);
        if !estimate.fits_usize {
            eprintln!(
                "acx: brute keyspace {} cannot be executed with the current usize index limit",
                estimate.keyspace
            );
            return ExitCode::from(EXIT_USAGE);
        }
        let attack = AttackFingerprint::new("brute", set.signature());
        let source = match set.into_source(start_index) {
            Ok(source) => source,
            Err(error) => {
                eprintln!("acx: {error}");
                return ExitCode::from(EXIT_USAGE);
            }
        };
        let total = source.total();
        (
            None,
            attack,
            Box::new(source) as Box<dyn CandidateSource>,
            total,
            "Candidates",
        )
    } else if use_hybrid {
        let dictionary = cli
            .dictionary
            .as_ref()
            .expect("validated hybrid dictionary");
        let fingerprint = match FileFingerprint::from_path(dictionary) {
            Ok(fingerprint) => fingerprint,
            Err(error) => {
                eprintln!("acx: {error}");
                return ExitCode::from(EXIT_USAGE);
            }
        };
        let set = match HybridSet::parse(
            dictionary,
            &cli.rules,
            cli.prefix_mask.as_deref(),
            cli.suffix_mask.as_deref(),
            &custom_texts,
        ) {
            Ok(set) => set,
            Err(error) => {
                eprintln!("acx: {error}");
                return ExitCode::from(EXIT_USAGE);
            }
        };
        let estimate = set.estimate(cli.threads);
        let (rate, rate_label) = rate_for(info.format);
        let seconds = estimate.total as f64 / rate;
        if seconds > 86_400.0 {
            eprintln!(
                "WARNING: estimated {} exceeds 24h on {rate_label} at the measured rate",
                format_duration(seconds)
            );
        }
        for warning in &estimate.warnings {
            eprintln!("WARNING: {warning}");
        }
        println!("Dictionary lines: {}", estimate.dict_lines);
        println!("Variants per line: {}", estimate.variants_per_line);
        println!("Hybrid keyspace: {}", estimate.total);
        print_space(&estimate.space);
        if !estimate.fits_usize {
            eprintln!(
                "acx: hybrid total {} cannot be executed with the current usize index limit",
                estimate.total
            );
            return ExitCode::from(EXIT_USAGE);
        }
        let attack = AttackFingerprint::new("hybrid", set.signature());
        let source = match set.into_source(start_index) {
            Ok(source) => source,
            Err(error) => {
                eprintln!("acx: {error}");
                return ExitCode::from(EXIT_USAGE);
            }
        };
        let total = source.total();
        (
            Some(fingerprint),
            attack,
            Box::new(source) as Box<dyn CandidateSource>,
            total,
            "Candidates",
        )
    } else if use_mask {
        let set = match MaskSet::parse(&cli.mask, &custom_texts) {
            Ok(set) => set,
            Err(error) => {
                eprintln!("acx: {error}");
                return ExitCode::from(EXIT_USAGE);
            }
        };
        let estimate = set.estimate(cli.threads);
        for warning in &estimate.warnings {
            eprintln!("WARNING: {warning}");
        }
        let (rate, label) = rate_for(info.format);
        let seconds = estimate.keyspace as f64 / rate;
        if seconds > 86_400.0 {
            eprintln!(
                "WARNING: estimated {} exceeds 24h on {label} at the measured rate",
                format_duration(seconds)
            );
        }
        println!("Mask keyspace: {}", estimate.keyspace);
        print_space(&estimate.space);
        if !estimate.fits_usize {
            eprintln!(
                "acx: mask keyspace {} cannot be executed with the current usize index limit",
                estimate.keyspace
            );
            return ExitCode::from(EXIT_USAGE);
        }
        let attack = AttackFingerprint::new("mask", set.signature());
        let source = match set.into_source(start_index) {
            Ok(source) => source,
            Err(error) => {
                eprintln!("acx: {error}");
                return ExitCode::from(EXIT_USAGE);
            }
        };
        let total = source.total();
        (
            None,
            attack,
            Box::new(source) as Box<dyn CandidateSource>,
            total,
            "Candidates",
        )
    } else {
        let dictionary = cli.dictionary.as_ref().expect("validated dict path");
        let fingerprint = match FileFingerprint::from_path(dictionary) {
            Ok(fingerprint) => fingerprint,
            Err(error) => {
                eprintln!("acx: {error}");
                return ExitCode::from(EXIT_USAGE);
            }
        };
        let dictionary = match DictionaryStream::open(dictionary, start_index) {
            Ok(dictionary) => dictionary,
            Err(error) => {
                eprintln!("acx: {error}");
                return ExitCode::from(EXIT_USAGE);
            }
        };
        let total = dictionary.total();
        (
            Some(fingerprint),
            AttackFingerprint::dictionary(),
            Box::new(dictionary) as Box<dyn CandidateSource>,
            total,
            "Passwords",
        )
    };

    println!("{label}: {total}");
    if total == 0 {
        eprintln!("acx: attack contains no candidates");
        return ExitCode::from(EXIT_USAGE);
    }

    if let Some(checkpoint) = loaded_checkpoint.as_ref() {
        if let Err(error) = checkpoint.validate(
            &archive_fingerprint,
            dictionary_fingerprint.as_ref(),
            &attack,
            total as u64,
        ) {
            eprintln!("acx: {error}");
            return ExitCode::from(EXIT_USAGE);
        }
        println!(
            "Resume: {} (candidate {start_index}/{total}, tried {})",
            checkpoint_path.display(),
            checkpoint.tried
        );
    }

    if start_index >= total {
        let _ = store.remove();
        println!("NOT FOUND");
        return ExitCode::from(EXIT_NOT_FOUND);
    }

    let initial = Checkpoint::new(
        archive_fingerprint.clone(),
        dictionary_fingerprint.clone(),
        attack.clone(),
        cli.threads.clamp(1, 256),
        start_index as u64,
        tried,
        total as u64,
    );
    if let Err(error) = store.save(&initial) {
        eprintln!("acx: could not write initial checkpoint: {error}");
        return ExitCode::from(EXIT_ARCHIVE);
    }

    println!("Checkpoint: {}", checkpoint_path.display());
    let context = RunContext::new(total, start_index, tried, cli.threads);
    if let Err(error) = install_stop_handler(context.control_arc()) {
        eprintln!("acx: Ctrl+C handler unavailable: {error}");
    }
    if std::io::stdin().is_terminal() {
        start_console_control(context.control_arc());
        eprintln!("Controls: p pause, r resume, s stop (Ctrl+C also stops)");
    }

    let finished = Arc::new(AtomicBool::new(false));
    let monitor_error = Arc::new(Mutex::new(None::<String>));
    let monitor = start_checkpoint_monitor(
        store.clone(),
        Arc::clone(&context),
        archive_fingerprint.clone(),
        dictionary_fingerprint.clone(),
        attack.clone(),
        Arc::clone(&finished),
        Arc::clone(&monitor_error),
    );

    let outcome = scheduler::run_with_source(factory, source, Arc::clone(&context));
    finished.store(true, Ordering::SeqCst);
    let _ = monitor.join();
    if let Some(error) = monitor_error
        .lock()
        .ok()
        .and_then(|slot| slot.as_ref().cloned())
    {
        eprintln!("acx: checkpoint monitor: {error}");
    }

    match outcome {
        Ok(RunOutcome::Found(hit)) => {
            let password = String::from_utf8_lossy(&hit.password);
            println!("FOUND: {password}");
            if let Err(error) = store.remove() {
                eprintln!(
                    "acx: could not remove checkpoint {}: {error}; refusing to leave a resumable checkpoint",
                    store.path().display()
                );
                return ExitCode::from(EXIT_ARCHIVE);
            }
            ExitCode::SUCCESS
        }
        Ok(RunOutcome::Exhausted) => {
            if let Err(error) = store.remove() {
                eprintln!("acx: could not remove checkpoint: {error}");
            }
            println!("NOT FOUND");
            ExitCode::from(EXIT_NOT_FOUND)
        }
        Ok(RunOutcome::Stopped(progress)) => {
            let checkpoint = Checkpoint::new(
                archive_fingerprint,
                dictionary_fingerprint,
                attack,
                context.threads(),
                progress.completed_through,
                progress.tried,
                progress.total,
            );
            if let Err(error) = store.save(&checkpoint) {
                eprintln!("acx: could not save checkpoint: {error}");
                return ExitCode::from(EXIT_ARCHIVE);
            }
            println!(
                "STOPPED: checkpoint {} (candidate {}/{})",
                store.path().display(),
                progress.completed_through,
                progress.total
            );
            ExitCode::from(EXIT_STOPPED)
        }
        Err(error) => {
            let progress = context.snapshot();
            if progress.tried > 0 {
                let checkpoint = Checkpoint::new(
                    archive_fingerprint,
                    dictionary_fingerprint,
                    attack,
                    context.threads(),
                    progress.completed_through,
                    progress.tried,
                    progress.total,
                );
                if let Err(save_error) = store.save(&checkpoint) {
                    eprintln!("acx: could not save checkpoint: {save_error}");
                }
            }
            eprintln!("acx: {error}");
            let exit = if matches!(&error, AcxError::Dictionary(_) | AcxError::Attack(_)) {
                EXIT_USAGE
            } else {
                EXIT_ARCHIVE
            };
            ExitCode::from(exit)
        }
    }
}

fn custom_texts(cli: &Cli) -> [Option<String>; 4] {
    [
        cli.custom_charset1.clone(),
        cli.custom_charset2.clone(),
        cli.custom_charset3.clone(),
        cli.custom_charset4.clone(),
    ]
}

fn rate_for(format: ArchiveFormat) -> (f64, &'static str) {
    match format {
        ArchiveFormat::Zip => (25_409.0, "ZIP AES"),
        ArchiveFormat::SevenZ => (967.9, "7z AES"),
        ArchiveFormat::Rar4 => (221.5, "RAR4 external"),
        ArchiveFormat::Rar5 => (1_727.2, "RAR5 check"),
    }
}

fn print_space(space: &acx_core::estimate::SpaceEstimate) {
    println!(
        "Watermark bitmap: {} ({} candidates)",
        format_bytes(space.watermark_bytes),
        space.total
    );
    println!(
        "Estimated peak (core): {} (+ archive sessions, {} batches in flight)",
        format_bytes(space.estimated_peak_bytes),
        space.in_flight_batches
    );
    for warning in &space.warnings {
        eprintln!("WARNING: {warning}");
    }
}

/// Decimal units keep the CLI and the task docs consistent (`182.9 MB`).
fn format_bytes(bytes: u128) -> String {
    if bytes < 1_000 {
        format!("{bytes} B")
    } else if bytes < 1_000_000 {
        format!("{:.1} KB", bytes as f64 / 1_000.0)
    } else if bytes < 1_000_000_000 {
        format!("{:.1} MB", bytes as f64 / 1_000_000.0)
    } else {
        format!("{:.2} GB", bytes as f64 / 1_000_000_000.0)
    }
}

fn estimate_attack(
    cli: &Cli,
    info: &acx_core::archive::ArchiveInfo,
    use_brute: bool,
    use_hybrid: bool,
) -> ExitCode {
    if use_brute {
        estimate_brute(cli, info)
    } else if use_hybrid {
        estimate_hybrid(cli, info)
    } else {
        estimate_mask(cli, info)
    }
}

fn estimate_brute(cli: &Cli, info: &acx_core::archive::ArchiveInfo) -> ExitCode {
    let charset_text = cli.brute.as_deref().expect("validated --brute");
    let min_len = cli.min_len.expect("validated --min-len");
    let max_len = cli.max_len.expect("validated --max-len");
    let set = match BruteSet::parse(charset_text, &custom_texts(cli), min_len, max_len) {
        Ok(set) => set,
        Err(error) => {
            eprintln!("acx: {error}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    let estimate = set.estimate(cli.threads);
    println!("Brute charset: {charset_text}");
    println!("Lengths: {min_len}..={max_len}");
    println!("Keyspace: {}", estimate.keyspace);
    println!("Fits executable index: {}", estimate.fits_usize);
    for (offset, keyspace) in estimate.per_len.iter().enumerate() {
        println!("Length {}: {keyspace}", min_len + offset);
    }
    for warning in &estimate.warnings {
        eprintln!("WARNING: {warning}");
    }
    print_space(&estimate.space);

    let (rate, label) = rate_for(info.format);
    let seconds = estimate.keyspace as f64 / rate;
    let capacity = rate * 86_400.0;
    println!("Format: {label} ({rate:.1}/s measured)");
    println!("ETA: {}", format_duration(seconds));
    println!("24h capacity: {capacity:.0} candidates");
    if seconds > 86_400.0 {
        eprintln!(
            "WARNING: estimated {} exceeds 24h at the measured rate; reduce the charset or --max-len",
            format_duration(seconds)
        );
    }
    ExitCode::SUCCESS
}

fn estimate_hybrid(cli: &Cli, info: &acx_core::archive::ArchiveInfo) -> ExitCode {
    let dictionary = cli
        .dictionary
        .as_ref()
        .expect("validated hybrid dictionary");
    let set = match HybridSet::parse(
        dictionary,
        &cli.rules,
        cli.prefix_mask.as_deref(),
        cli.suffix_mask.as_deref(),
        &custom_texts(cli),
    ) {
        Ok(set) => set,
        Err(error) => {
            eprintln!("acx: {error}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    let estimate = set.estimate(cli.threads);
    println!("Dictionary lines: {}", estimate.dict_lines);
    println!("Variants per line: {}", estimate.variants_per_line);
    println!("Total candidates: {}", estimate.total);
    println!("Fits executable index: {}", estimate.fits_usize);
    print_space(&estimate.space);
    for warning in &estimate.warnings {
        eprintln!("WARNING: {warning}");
    }

    let (rate, label) = rate_for(info.format);
    let seconds = estimate.total as f64 / rate;
    let capacity = rate * 86_400.0;
    println!("Format: {label} ({rate:.1}/s measured)");
    println!("ETA: {}", format_duration(seconds));
    println!("24h capacity: {capacity:.0} candidates");
    if seconds > 86_400.0 {
        eprintln!(
            "WARNING: estimated {} exceeds 24h at the measured rate; reduce the dictionary or variants",
            format_duration(seconds)
        );
    }
    ExitCode::SUCCESS
}

fn estimate_mask(cli: &Cli, info: &acx_core::archive::ArchiveInfo) -> ExitCode {
    let custom = custom_texts(cli);
    let set = match MaskSet::parse(&cli.mask, &custom) {
        Ok(set) => set,
        Err(error) => {
            eprintln!("acx: {error}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    let estimate = set.estimate(cli.threads);
    println!("Mask: {}", cli.mask.join(" | "));
    println!("Keyspace: {}", estimate.keyspace);
    println!("Fits executable index: {}", estimate.fits_usize);
    for warning in &estimate.warnings {
        eprintln!("WARNING: {warning}");
    }
    print_space(&estimate.space);

    let (rate, label) = rate_for(info.format);
    let seconds = estimate.keyspace as f64 / rate;
    let capacity = rate * 86_400.0;
    println!("Format: {label} ({rate:.1}/s measured)");
    println!("ETA: {}", format_duration(seconds));
    println!("24h capacity: {capacity:.0} candidates");
    if seconds > 86_400.0 {
        eprintln!(
            "WARNING: estimated {} exceeds 24h at the measured rate; reduce mask/charset or use multiple masks",
            format_duration(seconds)
        );
    }
    ExitCode::SUCCESS
}

fn format_duration(seconds: f64) -> String {
    if !seconds.is_finite() || seconds < 0.0 {
        return "unknown".to_string();
    }
    if seconds < 60.0 {
        format!("{seconds:.1}s")
    } else if seconds < 3_600.0 {
        format!("{:.1}min", seconds / 60.0)
    } else if seconds < 86_400.0 {
        format!("{:.1}h", seconds / 3_600.0)
    } else if seconds < 31_557_600.0 {
        format!("{:.1}days", seconds / 86_400.0)
    } else {
        format!("{:.1}years", seconds / 31_557_600.0)
    }
}

fn default_checkpoint_path(archive: &std::path::Path) -> PathBuf {
    PathBuf::from(format!("{}.acx-checkpoint", archive.display()))
}

fn start_checkpoint_monitor(
    store: CheckpointStore,
    context: Arc<RunContext>,
    archive: ArchiveFingerprint,
    dictionary: Option<FileFingerprint>,
    attack: AttackFingerprint,
    finished: Arc<AtomicBool>,
    error_slot: Arc<Mutex<Option<String>>>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(1));
        if finished.load(Ordering::SeqCst) {
            break;
        }
        if context.has_found() {
            // The hit is in memory; never persist a checkpoint that could make
            // a later --resume skip it.
            break;
        }
        let progress = context.snapshot();
        if progress.tried == 0 {
            continue;
        }
        let checkpoint = Checkpoint::new(
            archive.clone(),
            dictionary.clone(),
            attack.clone(),
            context.threads(),
            progress.completed_through,
            progress.tried,
            progress.total,
        );
        if let Err(error) = store.save(&checkpoint) {
            if let Ok(mut slot) = error_slot.lock() {
                *slot = Some(error.to_string());
            }
            break;
        }
    })
}

/// Optional TTY control loop. It is detached: when the run finishes the process
/// exits even though this thread is blocked on stdin.
fn start_console_control(control: Arc<RunControl>) {
    thread::spawn(move || {
        let mut line = String::new();
        loop {
            line.clear();
            match std::io::stdin().read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
            match line.trim().to_ascii_lowercase().as_str() {
                "p" => {
                    if control.pause() {
                        eprintln!("PAUSED (r=resume, s=stop)");
                    } else {
                        eprintln!("cannot pause in the current state");
                    }
                }
                "r" => {
                    if control.resume() {
                        eprintln!("RESUMED");
                    } else {
                        eprintln!("not paused");
                    }
                }
                "s" | "q" => {
                    eprintln!("STOPPING (checkpoint will be saved)");
                    control.stop();
                    break;
                }
                "" => {}
                _ => eprintln!("unknown control (p=pause, r=resume, s=stop)"),
            }
        }
    });
}

#[cfg(windows)]
fn install_stop_handler(control: Arc<RunControl>) -> Result<(), String> {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::OnceLock;
    use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;

    static CONTROL: OnceLock<Arc<RunControl>> = OnceLock::new();
    static PRESSES: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "system" fn handler(_event: u32) -> i32 {
        if let Some(control) = CONTROL.get() {
            if PRESSES.fetch_add(1, Ordering::SeqCst) == 0 {
                control.stop();
            } else {
                control.force_stop();
            }
        }
        1
    }

    CONTROL
        .set(control)
        .map_err(|_| "Ctrl+C handler already installed".to_string())?;
    // SAFETY: the handler has C ABI and lives for the process lifetime.
    let installed = unsafe { SetConsoleCtrlHandler(Some(handler), 1) };
    if installed == 0 {
        Err("SetConsoleCtrlHandler failed".to_string())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
fn install_stop_handler(_control: Arc<RunControl>) -> Result<(), String> {
    // W1 is Windows-first. Other platforms keep the default SIGINT behavior;
    // the core RunControl API is still available to future frontends.
    Ok(())
}
