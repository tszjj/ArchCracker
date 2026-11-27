// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

//! ArchCracker command-line interface: single-task attacks and batch manifests.

use acx_core::archive::{ArchiveFormat, ArchiveInfo};
use acx_core::batch::{self, BatchConfig, BatchControl, BatchOptions};
use acx_core::estimate::SpaceEstimate;
use acx_core::job::{
    self, AttackConfig, EstimateDetail, JobEstimate, JobObserver, JobPreview, JobReport, JobSpec,
    JobStatus,
};
use acx_core::scheduler::RunControl;
use clap::{Args, Parser, Subcommand};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
#[cfg(windows)]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

/// Exit code used when the archive is unusable (bad format, unencrypted, unsupported).
const EXIT_ARCHIVE: u8 = 3;
/// Exit code used for arguments, manifests, dictionaries, and resume problems.
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
    long_about = None,
    args_conflicts_with_subcommands = true
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    #[command(flatten)]
    single: SingleArgs,
}

#[derive(Subcommand)]
enum Command {
    /// Run every job in a TOML manifest, isolating task failures.
    Batch(BatchArgs),
}

#[derive(Args)]
struct BatchArgs {
    /// TOML batch manifest.
    #[arg(value_name = "MANIFEST")]
    manifest: PathBuf,

    /// Override the manifest's max_parallel (1..=256).
    #[arg(long = "max-parallel", value_name = "N")]
    max_parallel: Option<usize>,

    /// Enable reuse of confirmed passwords inside this batch (memory only).
    #[arg(long = "reuse-found")]
    reuse_found: bool,

    /// Stop scheduling new tasks after the first failed task.
    #[arg(long = "fail-fast")]
    fail_fast: bool,

    /// Print per-job estimates without starting an attack or writing checkpoints.
    #[arg(long = "dry-run")]
    dry_run: bool,
}

#[derive(Args)]
struct SingleArgs {
    /// Archive to recover (ZIP, 7z, or RAR via a user-installed UnRAR).
    #[arg(short = 'f', long = "file", value_name = "PATH")]
    file: Option<PathBuf>,

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
    match cli.command {
        Some(Command::Batch(args)) => run_batch_command(args),
        None => run_single(cli.single),
    }
}

fn run_single(cli: SingleArgs) -> ExitCode {
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
    let Some(file) = cli.file.clone() else {
        eprintln!("acx: single-task mode requires --file; run `acx batch <manifest>` for a batch");
        return ExitCode::from(EXIT_USAGE);
    };
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

    let spec = JobSpec {
        id: file
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or("job")
            .to_string(),
        archive: file.clone(),
        attack: attack_from_cli(&cli, use_brute, use_mask, use_hybrid),
        threads: cli.threads,
        checkpoint: cli
            .checkpoint
            .clone()
            .unwrap_or_else(|| default_checkpoint_path(&file)),
        resume: cli.resume,
    };

    if cli.estimate {
        let estimate = match job::estimate_job(&spec) {
            Ok(estimate) => estimate,
            Err(error) => {
                eprintln!("acx: {error}");
                return ExitCode::from(exit_for_error(&error));
            }
        };
        print_archive(&estimate.info);
        print_estimate(&estimate);
        return ExitCode::SUCCESS;
    }

    let control = Arc::new(RunControl::new());
    if let Err(error) = install_stop_handler(Arc::clone(&control)) {
        eprintln!("acx: Ctrl+C handler unavailable: {error}");
    }
    if std::io::stdin().is_terminal() {
        start_console_control(Arc::clone(&control));
        eprintln!("Controls: p pause, r resume, s stop (Ctrl+C also stops)");
    }

    match job::run_job(&spec, control, &[], &mut CliObserver) {
        Ok(report) => exit_for_report(&report),
        Err(error) => {
            eprintln!("acx: {error}");
            ExitCode::from(exit_for_error(&error))
        }
    }
}

fn attack_from_cli(
    cli: &SingleArgs,
    use_brute: bool,
    use_mask: bool,
    use_hybrid: bool,
) -> AttackConfig {
    let custom = custom_texts(cli);
    if use_brute {
        AttackConfig::Brute {
            charset: cli.brute.clone().expect("validated --brute"),
            min_len: cli.min_len.expect("validated --min-len"),
            max_len: cli.max_len.expect("validated --max-len"),
            custom,
        }
    } else if use_mask {
        AttackConfig::Mask {
            masks: cli.mask.clone(),
            custom,
        }
    } else if use_hybrid {
        AttackConfig::Hybrid {
            dictionary: cli.dictionary.clone().expect("validated dictionary"),
            rules: cli.rules.clone(),
            prefix_mask: cli.prefix_mask.clone(),
            suffix_mask: cli.suffix_mask.clone(),
            custom,
        }
    } else {
        AttackConfig::Dictionary {
            dictionary: cli.dictionary.clone().expect("validated dictionary"),
        }
    }
}

fn custom_texts(cli: &SingleArgs) -> [Option<String>; 4] {
    [
        cli.custom_charset1.clone(),
        cli.custom_charset2.clone(),
        cli.custom_charset3.clone(),
        cli.custom_charset4.clone(),
    ]
}

struct CliObserver;

impl JobObserver for CliObserver {
    fn prepared(&mut self, preview: &JobPreview) {
        print_archive(&preview.estimate.info);
        print_attack_summary(&preview.estimate);
        if preview.resumed {
            println!(
                "Resume: {} (candidate {}/{}, tried {})",
                preview.checkpoint.display(),
                preview.start_index,
                preview.estimate.total,
                preview.tried
            );
        }
        println!("Checkpoint: {}", preview.checkpoint.display());
    }
}

fn print_archive(info: &ArchiveInfo) {
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
}

/// Pre-attack summary printed before an actual run.
fn print_attack_summary(estimate: &JobEstimate) {
    match &estimate.detail {
        EstimateDetail::Dictionary => println!("Passwords: {}", estimate.total),
        EstimateDetail::Mask { .. } => println!("Mask keyspace: {}", estimate.total),
        EstimateDetail::Brute {
            charset,
            min_len,
            max_len,
            ..
        } => {
            println!("Brute charset: {charset}");
            println!("Lengths: {min_len}..={max_len}");
            println!("Brute keyspace: {}", estimate.total);
        }
        EstimateDetail::Hybrid {
            dict_lines,
            variants_per_line,
        } => {
            println!("Dictionary lines: {dict_lines}");
            println!("Variants per line: {variants_per_line}");
            println!("Hybrid keyspace: {}", estimate.total);
        }
    }
    print_space(&estimate.space);
    for warning in &estimate.warnings {
        eprintln!("WARNING: {warning}");
    }
    warn_if_slow(estimate);
}

/// Estimate-mode output: mode details, space, then format/ETA/capacity.
fn print_estimate(estimate: &JobEstimate) {
    match &estimate.detail {
        EstimateDetail::Dictionary => {
            println!("Passwords: {}", estimate.total);
            println!("Fits executable index: true");
        }
        EstimateDetail::Mask { masks, per_mask } => {
            println!("Mask: {}", masks.join(" | "));
            println!("Keyspace: {}", estimate.total);
            println!("Fits executable index: {}", estimate.fits_usize);
            for (index, keyspace) in per_mask.iter().enumerate() {
                println!("Mask {}: {keyspace}", index + 1);
            }
        }
        EstimateDetail::Brute {
            charset,
            min_len,
            max_len,
            per_len,
        } => {
            println!("Brute charset: {charset}");
            println!("Lengths: {min_len}..={max_len}");
            println!("Keyspace: {}", estimate.total);
            println!("Fits executable index: {}", estimate.fits_usize);
            for (offset, keyspace) in per_len.iter().enumerate() {
                println!("Length {}: {keyspace}", min_len + offset);
            }
        }
        EstimateDetail::Hybrid {
            dict_lines,
            variants_per_line,
        } => {
            println!("Dictionary lines: {dict_lines}");
            println!("Variants per line: {variants_per_line}");
            println!("Total candidates: {}", estimate.total);
            println!("Fits executable index: {}", estimate.fits_usize);
        }
    }
    print_space(&estimate.space);
    for warning in &estimate.warnings {
        eprintln!("WARNING: {warning}");
    }

    let (rate, label) = rate_for(estimate.info.format);
    let seconds = estimate.total as f64 / rate;
    let capacity = rate * 86_400.0;
    println!("Format: {label} ({rate:.1}/s measured)");
    println!("ETA: {}", format_duration(seconds));
    println!("24h capacity: {capacity:.0} candidates");
    warn_if_over_24h(seconds);
}

fn print_space(space: &SpaceEstimate) {
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

fn warn_if_slow(estimate: &JobEstimate) {
    let (rate, label) = rate_for(estimate.info.format);
    let seconds = estimate.total as f64 / rate;
    if seconds > 86_400.0 {
        eprintln!(
            "WARNING: estimated {} exceeds 24h on {label} at the measured rate",
            format_duration(seconds)
        );
    }
}

fn warn_if_over_24h(seconds: f64) {
    if seconds > 86_400.0 {
        eprintln!(
            "WARNING: estimated {} exceeds 24h at the measured rate; reduce the keyspace or variants",
            format_duration(seconds)
        );
    }
}

fn exit_for_report(report: &JobReport) -> ExitCode {
    for warning in &report.warnings {
        eprintln!("acx: {warning}");
    }
    match report.status {
        JobStatus::Found => {
            let password = report
                .password
                .as_deref()
                .map(String::from_utf8_lossy)
                .unwrap_or_default();
            println!("FOUND: {password}");
            ExitCode::SUCCESS
        }
        JobStatus::NotFound => {
            println!("NOT FOUND");
            ExitCode::from(EXIT_NOT_FOUND)
        }
        JobStatus::Stopped => {
            println!(
                "STOPPED: checkpoint {} (candidate {}/{})",
                report.checkpoint.display(),
                report.completed_through,
                report.total
            );
            ExitCode::from(EXIT_STOPPED)
        }
        JobStatus::Cancelled => ExitCode::from(EXIT_STOPPED),
        JobStatus::Failed => {
            if let Some(error) = &report.error {
                eprintln!("acx: {error}");
                ExitCode::from(exit_for_error(error))
            } else {
                eprintln!("acx: job failed");
                ExitCode::from(EXIT_ARCHIVE)
            }
        }
    }
}

fn exit_for_error(error: &acx_core::error::AcxError) -> u8 {
    use acx_core::error::AcxError;
    match error {
        AcxError::Attack(_)
        | AcxError::Batch(_)
        | AcxError::Checkpoint(_)
        | AcxError::Dictionary(_) => EXIT_USAGE,
        _ => EXIT_ARCHIVE,
    }
}

fn rate_for(format: ArchiveFormat) -> (f64, &'static str) {
    match format {
        ArchiveFormat::Zip => (25_409.0, "ZIP AES"),
        ArchiveFormat::SevenZ => (967.9, "7z AES"),
        ArchiveFormat::Rar4 => (221.5, "RAR4 external"),
        ArchiveFormat::Rar5 => (1_727.2, "RAR5 check"),
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
    } else if bytes < 1_000_000_000_000 {
        format!("{:.2} GB", bytes as f64 / 1_000_000_000.0)
    } else if bytes < 1_000_000_000_000_000 {
        format!("{:.2} TB", bytes as f64 / 1_000_000_000_000.0)
    } else if bytes < 1_000_000_000_000_000_000 {
        format!("{:.2} PB", bytes as f64 / 1_000_000_000_000_000.0)
    } else {
        format!("{:.2} EB", bytes as f64 / 1_000_000_000_000_000_000.0)
    }
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

fn default_checkpoint_path(archive: &Path) -> PathBuf {
    PathBuf::from(format!("{}.acx-checkpoint", archive.display()))
}

fn run_batch_command(args: BatchArgs) -> ExitCode {
    let config = match batch::load_manifest(&args.manifest) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("acx: {error}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    for warning in &config.warnings {
        eprintln!("WARNING: {warning}");
    }
    if args.dry_run {
        return dry_run(&config, args.max_parallel);
    }
    if let Some(max_parallel) = args.max_parallel {
        if max_parallel == 0 || max_parallel > 256 {
            eprintln!("acx: --max-parallel must be 1..=256");
            return ExitCode::from(EXIT_USAGE);
        }
    }
    let control = Arc::new(BatchControl::new());
    if let Err(error) = install_batch_stop_handler(Arc::clone(&control)) {
        eprintln!("acx: Ctrl+C handler unavailable: {error}");
    }
    let options = BatchOptions {
        max_parallel: args.max_parallel,
        reuse_found: args.reuse_found.then_some(true),
        fail_fast: args.fail_fast,
        control,
    };
    let report = match batch::run_batch(&config, &options) {
        Ok(report) => report,
        Err(error) => {
            eprintln!("acx: {error}");
            return ExitCode::from(EXIT_USAGE);
        }
    };

    for task in &report.tasks {
        match task.report.status {
            JobStatus::Found => {
                let password = task
                    .report
                    .password
                    .as_deref()
                    .map(String::from_utf8_lossy)
                    .unwrap_or_default();
                let reused = if task.report.reused { " (reused)" } else { "" };
                println!("[{0}] FOUND: {password}{reused}", task.id);
            }
            JobStatus::NotFound => println!(
                "[{0}] NOT FOUND (tried {1}/{2})",
                task.id, task.report.tried, task.report.total
            ),
            JobStatus::Stopped => println!(
                "[{0}] STOPPED (checkpoint {1}, candidate {2}/{3})",
                task.id,
                task.report.checkpoint.display(),
                task.report.completed_through,
                task.report.total
            ),
            JobStatus::Cancelled => println!("[{}] CANCELLED", task.id),
            JobStatus::Failed => {
                let error = task
                    .report
                    .error
                    .as_ref()
                    .map(std::string::ToString::to_string)
                    .unwrap_or_else(|| "unknown failure".to_string());
                eprintln!("[{}] FAILED: {error}", task.id);
            }
        }
        for warning in &task.report.warnings {
            eprintln!("[{}] {warning}", task.id);
        }
    }
    println!(
        "Batch summary: {} found, {} not found, {} failed, {} cancelled",
        report.found_count(),
        report
            .tasks
            .iter()
            .filter(|task| task.report.status == JobStatus::NotFound)
            .count(),
        report.failed_count(),
        report
            .tasks
            .iter()
            .filter(|task| task.report.status == JobStatus::Cancelled)
            .count()
    );

    if report.stopped
        || report
            .tasks
            .iter()
            .any(|task| task.report.status == JobStatus::Stopped)
    {
        ExitCode::from(EXIT_STOPPED)
    } else if report.any_failed() {
        ExitCode::from(EXIT_ARCHIVE)
    } else if report.any_found() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(EXIT_NOT_FOUND)
    }
}

fn dry_run(config: &BatchConfig, max_parallel: Option<usize>) -> ExitCode {
    if let Some(max_parallel) = max_parallel {
        if max_parallel == 0 || max_parallel > 256 {
            eprintln!("acx: --max-parallel must be 1..=256");
            return ExitCode::from(EXIT_USAGE);
        }
    }
    let parallel = max_parallel
        .unwrap_or(config.max_parallel)
        .clamp(1, config.jobs.len().max(1));
    let mut failed = false;
    let mut serial_seconds = 0.0f64;
    let mut peaks = Vec::new();
    for preview in batch::estimate_batch(config) {
        println!("Task: {}", preview.id);
        match preview.result {
            Ok(estimate) => {
                print_archive(&estimate.info);
                print_estimate(&estimate);
                let (rate, _) = rate_for(estimate.info.format);
                serial_seconds += estimate.total as f64 / rate;
                peaks.push(estimate.space.estimated_peak_bytes);
            }
            Err(error) => {
                eprintln!("acx: task `{}`: {error}", preview.id);
                failed = true;
            }
        }
        println!();
    }
    if failed {
        return ExitCode::from(EXIT_USAGE);
    }
    peaks.sort_unstable_by(|left, right| right.cmp(left));
    let peak_bytes: u128 = peaks.iter().take(parallel).sum();
    println!(
        "Batch estimate: {} jobs, serial ETA {}, peak core memory {} (max_parallel={parallel})",
        config.jobs.len(),
        format_duration(serial_seconds),
        format_bytes(peak_bytes)
    );
    ExitCode::SUCCESS
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
    // W1 is Windows-first. Other platforms keep the default SIGINT behavior.
    Ok(())
}

#[cfg(windows)]
fn install_batch_stop_handler(control: Arc<BatchControl>) -> Result<(), String> {
    use std::sync::OnceLock;
    use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;

    static CONTROL: OnceLock<Arc<BatchControl>> = OnceLock::new();
    static PRESSES: AtomicUsize = AtomicUsize::new(0);

    unsafe extern "system" fn handler(_event: u32) -> i32 {
        if let Some(control) = CONTROL.get() {
            if PRESSES.fetch_add(1, Ordering::SeqCst) == 0 {
                control.stop();
            } else {
                control.stop();
                std::process::exit(EXIT_STOPPED as i32);
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
fn install_batch_stop_handler(_control: Arc<BatchControl>) -> Result<(), String> {
    Ok(())
}
