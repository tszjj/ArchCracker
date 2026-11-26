// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

//! ArchCracker command-line interface (W1: ZIP, 7z, and external RAR).

use acx_core::archive::{
    self, ArchiveFormat, ArchiveSessionFactory, ArchiveSource, RarFactory, SevenZFactory,
    ZipFactory,
};
use acx_core::candidates::DictionaryStream;
use acx_core::checkpoint::{ArchiveFingerprint, Checkpoint, CheckpointStore, FileFingerprint};
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
            // `archive::preflight` already probed this RAR; reuse that result
            // instead of starting a second preflight in the factory.
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
    let dictionary_fingerprint = match FileFingerprint::from_path(&cli.dictionary) {
        Ok(fingerprint) => fingerprint,
        Err(error) => {
            eprintln!("acx: {error}");
            return ExitCode::from(EXIT_USAGE);
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

    let dictionary = match DictionaryStream::open(&cli.dictionary, start_index) {
        Ok(dictionary) => dictionary,
        Err(error) => {
            eprintln!("acx: {error}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    let total = dictionary.total();
    println!("Passwords: {total}");
    if total == 0 {
        eprintln!("acx: dictionary is empty");
        return ExitCode::from(EXIT_USAGE);
    }

    if let Some(checkpoint) = loaded_checkpoint.as_ref() {
        if let Err(error) = checkpoint.validate(
            &archive_fingerprint,
            &dictionary_fingerprint,
            "dict",
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
        "dict",
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
        Arc::clone(&finished),
        Arc::clone(&monitor_error),
    );

    let outcome = scheduler::run_with_source(factory, Box::new(dictionary), Arc::clone(&context));
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
                "dict",
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
                    "dict",
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
            let exit = if matches!(&error, AcxError::Dictionary(_)) {
                EXIT_USAGE
            } else {
                EXIT_ARCHIVE
            };
            ExitCode::from(exit)
        }
    }
}

fn default_checkpoint_path(archive: &std::path::Path) -> PathBuf {
    PathBuf::from(format!("{}.acx-checkpoint", archive.display()))
}

fn start_checkpoint_monitor(
    store: CheckpointStore,
    context: Arc<RunContext>,
    archive: ArchiveFingerprint,
    dictionary: FileFingerprint,
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
            "dict",
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
