// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors
//!
//! Local W1-010 latency harness (not a unit test; large fixtures are ignored).
//!
//! Usage:
//!   cargo run -p acx-cli --example w1_latency -- \
//!     <archive> <dictionary> <pause-stop|stop-correct> <threads>

use acx_core::archive::{
    self, ArchiveFormat, ArchiveSessionFactory, RarFactory, SevenZFactory, ZipFactory,
};
use acx_core::candidates::DictionaryStream;
use acx_core::scheduler::{self, RunContext, RunOutcome};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

fn factory(path: &PathBuf, info: &acx_core::archive::ArchiveInfo) -> Arc<dyn ArchiveSessionFactory> {
    match info.format {
        ArchiveFormat::Zip => Arc::new(ZipFactory { path: path.clone() }),
        ArchiveFormat::SevenZ => Arc::new(
            SevenZFactory::from_info(path.clone(), info.clone()).expect("7z factory"),
        ),
        ArchiveFormat::Rar4 | ArchiveFormat::Rar5 => {
            Arc::new(RarFactory::from_info(path.clone(), info.clone()).expect("RAR factory"))
        }
    }
}

fn main() {
    let mut args = std::env::args_os().skip(1);
    let path = PathBuf::from(args.next().expect("archive"));
    let dictionary = PathBuf::from(args.next().expect("dictionary"));
    let mode = args.next().expect("mode").to_string_lossy().to_string();
    let threads: usize = args
        .next()
        .expect("threads")
        .to_string_lossy()
        .parse()
        .expect("threads");

    let info = archive::preflight(&path).expect("preflight");
    let factory = factory(&path, &info);
    let source = DictionaryStream::open(&dictionary, 0).expect("dictionary");
    let total = source.total();
    let context = RunContext::new(total, 0, 0, threads);
    let control = context.control_arc();
    let started = Instant::now();
    let handle = thread::spawn(move || {
        scheduler::run_with_source(factory, Box::new(source), context)
    });

    if mode == "pause-stop" {
        thread::sleep(Duration::from_millis(150));
        let pause = Instant::now();
        let accepted = control.pause();
        let pause_state_ms = pause.elapsed().as_secs_f64() * 1000.0;
        thread::sleep(Duration::from_millis(200));
        let resumed = control.resume();
        thread::sleep(Duration::from_millis(100));
        let stop = Instant::now();
        control.stop();
        let outcome = handle.join().expect("join").expect("run");
        let stop_exit_ms = stop.elapsed().as_secs_f64() * 1000.0;
        println!(
            "mode=pause-stop accepted={accepted} pause_state_ms={pause_state_ms:.3} resumed={resumed} stop_exit_ms={stop_exit_ms:.3} total_ms={:.3} outcome={}",
            started.elapsed().as_secs_f64() * 1000.0,
            outcome_name(&outcome)
        );
    } else if mode == "stop-correct" {
        thread::sleep(Duration::from_millis(150));
        let stop = Instant::now();
        control.stop();
        let outcome = handle.join().expect("join").expect("run");
        println!(
            "mode=stop-correct stop_exit_ms={:.3} total_ms={:.3} outcome={}",
            stop.elapsed().as_secs_f64() * 1000.0,
            started.elapsed().as_secs_f64() * 1000.0,
            outcome_name(&outcome)
        );
    } else {
        panic!("mode must be pause-stop or stop-correct");
    }
}

fn outcome_name(outcome: &RunOutcome) -> &'static str {
    match outcome {
        RunOutcome::Found(_) => "Found",
        RunOutcome::Exhausted => "Exhausted",
        RunOutcome::Stopped(_) => "Stopped",
    }
}
