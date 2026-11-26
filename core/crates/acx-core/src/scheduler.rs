// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

//! Multi-threaded dictionary scheduler with run control and progress.
//!
//! The producer slices the candidate list into fixed-size index batches and
//! hands them to workers through a bounded channel. Every worker owns one
//! archive session and tests candidates until a hit, an error, or a stop.
//!
//! Pause/stop is cooperative: workers check [`RunControl`] between candidates.
//! A pause leaves workers and archive sessions alive and blocks the producer;
//! a stop asks external engines to cancel and returns [`RunOutcome::Stopped`]
//! with a candidate watermark that can be persisted by the CLI.
//!
//! Progress is tracked at candidate granularity, not by "most recent attempt".
//! The watermark only advances over a contiguous completed prefix, so a
//! concurrent run can never checkpoint past an untested candidate.

use crate::archive::{ArchiveSessionFactory, PasswordTest};
use crate::candidates::{CandidateBatch, CandidateSource};
use crate::engines::external::CancelToken;
use crate::error::{AcxError, Result};
use crossbeam_channel::{bounded, Receiver, RecvTimeoutError, SendTimeoutError};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Maximum candidates allowed in the scheduler pipeline at once.
///
/// The producer, queue and workers together must not hold more than this many
/// candidates; otherwise a hard kill can replay several 4096-candidate batches.
const MAX_IN_FLIGHT_CANDIDATES: usize = 4096;

/// Small queue; the per-batch size is derived from the worker count so the
/// total in-flight candidate window stays at `MAX_IN_FLIGHT_CANDIDATES`.
const PIPELINE_QUEUE_BATCHES: usize = 2;

/// Upper bound for worker threads; extra threads only add open sessions.
const MAX_THREADS: usize = 256;

/// How often workers poll control state while waiting for a batch.
const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// A verified password found by the scheduler.
#[derive(Debug, Clone)]
pub struct Hit {
    pub password: Vec<u8>,
    /// Number of candidates attempted when the hit was recorded.
    pub tried: u64,
}

/// Coarse scheduler state. Pause is not terminal; stop is.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunState {
    Running = 0,
    Paused = 1,
    Stopping = 2,
    Stopped = 3,
    Finished = 4,
}

impl RunState {
    fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Paused,
            2 => Self::Stopping,
            3 => Self::Stopped,
            4 => Self::Finished,
            _ => Self::Running,
        }
    }
}

/// Thread-safe pause/stop control shared by the CLI, GUI, and scheduler.
#[derive(Debug)]
pub struct RunControl {
    state: AtomicU8,
    cancel: CancelToken,
}

impl Default for RunControl {
    fn default() -> Self {
        Self::new()
    }
}

impl RunControl {
    pub fn new() -> Self {
        Self {
            state: AtomicU8::new(RunState::Running as u8),
            cancel: CancelToken::new(),
        }
    }

    /// Request a pause. Returns false when the run is already stopping or done.
    pub fn pause(&self) -> bool {
        self.state
            .compare_exchange(
                RunState::Running as u8,
                RunState::Paused as u8,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok()
    }

    /// Resume a paused run. No-op when not paused.
    pub fn resume(&self) -> bool {
        self.state
            .compare_exchange(
                RunState::Paused as u8,
                RunState::Running as u8,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok()
    }

    /// Request a graceful stop. External engines receive the cancel token.
    pub fn stop(&self) {
        let previous = self.state.swap(RunState::Stopping as u8, Ordering::SeqCst);
        if previous != RunState::Finished as u8 {
            self.cancel.cancel();
        }
    }

    /// Force stop is currently the same signal as stop; in-process candidate
    /// tests cannot be preempted, external child processes are killed.
    pub fn force_stop(&self) {
        self.stop();
    }

    pub fn state(&self) -> RunState {
        RunState::from_u8(self.state.load(Ordering::SeqCst))
    }

    pub fn is_paused(&self) -> bool {
        self.state() == RunState::Paused
    }

    pub fn is_stopping(&self) -> bool {
        matches!(self.state(), RunState::Stopping | RunState::Stopped)
    }

    pub fn cancel_token(&self) -> CancelToken {
        self.cancel.clone()
    }

    fn finish(&self) {
        self.state.store(RunState::Finished as u8, Ordering::SeqCst);
    }

    fn mark_stopped(&self) {
        self.state.store(RunState::Stopped as u8, Ordering::SeqCst);
    }
}

/// Immutable point-in-time progress used by checkpoint writers and the CLI.
#[derive(Debug, Clone)]
pub struct RunProgress {
    /// All candidates with index `< completed_through` have been tested.
    pub completed_through: u64,
    pub tried: u64,
    pub total: u64,
    pub elapsed: Duration,
}

/// Terminal result of a scheduler run.
#[derive(Debug)]
pub enum RunOutcome {
    Found(Hit),
    Exhausted,
    /// The run was stopped by `RunControl`; the progress watermark is safe for
    /// resuming (at most in-flight candidates are replayed).
    Stopped(RunProgress),
}

struct ProgressState {
    total: usize,
    /// One bit per candidate; `total/8` bytes, not a `Vec<bool>` or
    /// `Vec<AtomicBool>`. The watermark scan reads this compact frontier.
    completed: Vec<AtomicU64>,
    watermark: Mutex<usize>,
    tried: AtomicU64,
    started: Instant,
}

/// Shared run context. The CLI keeps one `Arc` and polls [`Self::snapshot`]
/// from its checkpoint monitor while the scheduler blocks.
pub struct RunContext {
    total: usize,
    start_index: usize,
    threads: usize,
    control: Arc<RunControl>,
    progress: ProgressState,
    found: AtomicBool,
}

impl RunContext {
    pub fn new(total: usize, start_index: usize, tried: u64, threads: usize) -> Arc<Self> {
        let start_index = start_index.min(total);
        Arc::new(Self {
            total,
            start_index,
            threads: threads.clamp(1, MAX_THREADS),
            control: Arc::new(RunControl::new()),
            progress: ProgressState {
                total,
                completed: (0..total.div_ceil(64)).map(|_| AtomicU64::new(0)).collect(),
                watermark: Mutex::new(start_index),
                tried: AtomicU64::new(tried),
                started: Instant::now(),
            },
            found: AtomicBool::new(false),
        })
    }

    pub fn control(&self) -> &RunControl {
        &self.control
    }

    /// Shared handle for a CLI signal handler or GUI control surface.
    pub fn control_arc(&self) -> Arc<RunControl> {
        Arc::clone(&self.control)
    }

    pub fn total(&self) -> usize {
        self.total
    }

    pub fn start_index(&self) -> usize {
        self.start_index
    }

    pub fn threads(&self) -> usize {
        self.threads
    }

    pub fn snapshot(&self) -> RunProgress {
        let watermark = match self.progress.watermark.lock() {
            Ok(guard) => *guard,
            Err(poisoned) => *poisoned.into_inner(),
        };
        RunProgress {
            completed_through: watermark as u64,
            tried: self.progress.tried.load(Ordering::SeqCst),
            total: self.total as u64,
            elapsed: self.progress.started.elapsed(),
        }
    }

    pub fn has_found(&self) -> bool {
        self.found.load(Ordering::SeqCst)
    }

    fn mark_found(&self) {
        self.found.store(true, Ordering::SeqCst);
    }

    fn record_tried(&self) -> u64 {
        self.progress.tried.fetch_add(1, Ordering::SeqCst) + 1
    }

    fn mark_completed(&self, index: usize) {
        if index >= self.progress.total {
            return;
        }
        let word = index / 64;
        let bit = 1u64 << (index % 64);
        self.progress.completed[word].fetch_or(bit, Ordering::SeqCst);
        let mut watermark = match self.progress.watermark.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        while *watermark < self.progress.total {
            let word = *watermark / 64;
            let bit = 1u64 << (*watermark % 64);
            if self.progress.completed[word].load(Ordering::SeqCst) & bit == 0 {
                break;
            }
            *watermark += 1;
        }
    }
}

/// Run a dictionary attack over `passwords` using `threads` workers.
///
/// This compatibility wrapper keeps the original "return only hit or
/// exhausted" behavior. New callers that need pause/stop should use
/// [`run_with_context`].
pub fn run(
    factory: Arc<dyn ArchiveSessionFactory>,
    passwords: Arc<Vec<Vec<u8>>>,
    threads: usize,
) -> Result<Option<Hit>> {
    let context = RunContext::new(passwords.len(), 0, 0, threads);
    match run_with_context(factory, passwords, context)? {
        RunOutcome::Found(hit) => Ok(Some(hit)),
        RunOutcome::Exhausted => Ok(None),
        RunOutcome::Stopped(_) => Err(AcxError::Internal(
            "scheduler stopped without an external stop request".to_string(),
        )),
    }
}

/// Run with a caller-owned [`RunContext`].
///
/// A pause blocks until [`RunControl::resume`] or [`RunControl::stop`]; worker
/// sessions stay alive. A stop returns `Stopped` with the largest safe
/// candidate watermark.
pub fn run_with_context(
    factory: Arc<dyn ArchiveSessionFactory>,
    passwords: Arc<Vec<Vec<u8>>>,
    context: Arc<RunContext>,
) -> Result<RunOutcome> {
    let total = passwords.len();
    if context.total != total {
        return Err(AcxError::Internal(format!(
            "run context total {} does not match dictionary {total}",
            context.total
        )));
    }
    let source = Box::new(MemorySource::new(passwords, context.start_index));
    run_with_source(factory, source, context)
}

/// Run with a bounded-memory [`CandidateSource`].
///
/// The source must already be positioned at `context.start_index`; the
/// scheduler verifies the first batch's start index before dispatching it.
pub fn run_with_source(
    factory: Arc<dyn ArchiveSessionFactory>,
    mut source: Box<dyn CandidateSource>,
    context: Arc<RunContext>,
) -> Result<RunOutcome> {
    let total = source.total();
    if context.total != total {
        return Err(AcxError::Internal(format!(
            "run context total {} does not match candidate source total {total}",
            context.total
        )));
    }
    if context.start_index >= total {
        context.control.finish();
        return Ok(RunOutcome::Exhausted);
    }

    let threads = context.threads;
    // Keep (workers + queue + producer's pending batch) × batch_size <= 4096.
    let batch_size = (MAX_IN_FLIGHT_CANDIDATES / (threads + PIPELINE_QUEUE_BATCHES + 1)).max(1);
    let (batch_tx, batch_rx) = bounded::<CandidateBatch>(PIPELINE_QUEUE_BATCHES);
    let hit: Arc<Mutex<Option<Hit>>> = Arc::new(Mutex::new(None));
    let mut first_error: Option<AcxError> = None;

    thread::scope(|scope| {
        let mut handles = Vec::with_capacity(threads);
        for _ in 0..threads {
            let batches: Receiver<CandidateBatch> = batch_rx.clone();
            let factory = Arc::clone(&factory);
            let context = Arc::clone(&context);
            let hit = Arc::clone(&hit);

            handles.push(scope.spawn(move || -> Result<()> {
                let result = worker_loop(factory.as_ref(), batches, &context, &hit);
                if result.is_err() {
                    context.control.stop();
                }
                result
            }));
        }

        // The producer must own no receiver while sending: once every worker
        // has exited, `send` has to observe the disconnect instead of blocking
        // forever on a full queue.
        drop(batch_rx);

        let mut expected_index = context.start_index;
        let mut pending: Option<CandidateBatch> = None;
        loop {
            if context.control.is_stopping() {
                break;
            }
            if context.control.is_paused() {
                thread::sleep(POLL_INTERVAL);
                continue;
            }

            let batch = match pending.take() {
                Some(batch) => batch,
                None => match source.next_batch(batch_size) {
                    Ok(Some(batch)) => batch,
                    Ok(None) => break,
                    Err(error) => {
                        first_error = Some(error);
                        context.control.stop();
                        break;
                    }
                },
            };
            if batch.start_index != expected_index || batch.candidates.is_empty() {
                first_error = Some(AcxError::Internal(format!(
                    "candidate source returned batch start {} while {} was expected",
                    batch.start_index, expected_index
                )));
                context.control.stop();
                break;
            }
            let batch_len = batch.candidates.len();

            match batch_tx.send_timeout(batch, POLL_INTERVAL) {
                Ok(()) => {
                    expected_index += batch_len;
                }
                Err(SendTimeoutError::Timeout(batch)) => pending = Some(batch),
                Err(SendTimeoutError::Disconnected(_)) => break,
            }
        }
        if first_error.is_none() && !context.control.is_stopping() && expected_index != total {
            first_error = Some(AcxError::Internal(format!(
                "candidate source ended at {expected_index} before total {total}"
            )));
            context.control.stop();
        }
        drop(batch_tx);

        for handle in handles {
            match handle.join() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
                Err(panic) => std::panic::resume_unwind(panic),
            }
        }
    });

    let found = match hit.lock() {
        Ok(mut slot) => slot.take(),
        Err(poisoned) => poisoned.into_inner().take(),
    };
    if let Some(hit) = found {
        // A verified hit wins over an error from another worker: the password
        // is already confirmed, and returning Err would make the CLI discard it.
        context.control.finish();
        return Ok(RunOutcome::Found(hit));
    }

    if let Some(error) = first_error {
        return Err(error);
    }

    let progress = context.snapshot();
    if context.control.is_stopping() {
        context.control.mark_stopped();
        Ok(RunOutcome::Stopped(progress))
    } else {
        context.control.finish();
        Ok(RunOutcome::Exhausted)
    }
}

/// In-memory source used by the legacy `run`/`run_with_context` APIs.
struct MemorySource {
    entries: Arc<Vec<Vec<u8>>>,
    next: usize,
}

impl MemorySource {
    fn new(entries: Arc<Vec<Vec<u8>>>, start_index: usize) -> Self {
        let next = start_index.min(entries.len());
        Self { entries, next }
    }
}

impl CandidateSource for MemorySource {
    fn total(&self) -> usize {
        self.entries.len()
    }

    fn next_batch(&mut self, max: usize) -> Result<Option<CandidateBatch>> {
        if max == 0 || self.next >= self.entries.len() {
            return Ok(None);
        }
        let start_index = self.next;
        let end = (start_index + max).min(self.entries.len());
        let candidates = self.entries[start_index..end].to_vec();
        self.next = end;
        Ok(Some(CandidateBatch {
            start_index,
            candidates,
        }))
    }
}

/// Consume batches until the source is exhausted, a hit is found, or stop is set.
fn worker_loop(
    factory: &dyn ArchiveSessionFactory,
    batches: Receiver<CandidateBatch>,
    context: &RunContext,
    hit: &Mutex<Option<Hit>>,
) -> Result<()> {
    let mut session = factory.open()?;
    session.set_cancel_token(context.control.cancel_token());

    loop {
        if context.control.is_stopping() {
            break;
        }
        if context.control.is_paused() {
            thread::sleep(POLL_INTERVAL);
            continue;
        }

        let batch = match batches.recv_timeout(POLL_INTERVAL) {
            Ok(batch) => batch,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        };

        for (offset, password) in batch.candidates.iter().enumerate() {
            let index = batch.start_index + offset;
            while context.control.is_paused() && !context.control.is_stopping() {
                thread::sleep(POLL_INTERVAL);
            }
            if context.control.is_stopping() {
                break;
            }

            match session.test_password(password) {
                Ok(PasswordTest::Hit) => {
                    let attempt = context.record_tried();
                    context.mark_found();
                    // Do not advance the completed watermark past a hit. If the
                    // process is killed between this hit and the CLI removing
                    // the checkpoint, resume must replay this candidate rather
                    // than start after the password.
                    let mut slot = match hit.lock() {
                        Ok(slot) => slot,
                        Err(poisoned) => poisoned.into_inner(),
                    };
                    if slot.is_none() {
                        *slot = Some(Hit {
                            password: password.clone(),
                            tried: attempt,
                        });
                    }
                    context.control.stop();
                    return Ok(());
                }
                Ok(PasswordTest::Miss) => {
                    context.record_tried();
                    context.mark_completed(index);
                }
                Err(AcxError::Cancelled) => return Ok(()),
                Err(error) => {
                    context.control.stop();
                    return Err(error);
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::{ArchiveFormat, ArchiveInfo, ArchiveSession, Encryption};
    use std::path::PathBuf;
    use std::sync::atomic::AtomicUsize;

    const SECRET: &[u8] = b"secret";

    /// In-memory session that records every candidate it is asked to test.
    struct FakeSession {
        info: ArchiveInfo,
        secret: Vec<u8>,
        attempts: Arc<Mutex<Vec<Vec<u8>>>>,
        delay: Duration,
    }

    impl ArchiveSession for FakeSession {
        fn info(&self) -> &ArchiveInfo {
            &self.info
        }

        fn test_password(&mut self, password: &[u8]) -> Result<PasswordTest> {
            if !self.delay.is_zero() {
                thread::sleep(self.delay);
            }
            let mut attempts = match self.attempts.lock() {
                Ok(attempts) => attempts,
                Err(poisoned) => poisoned.into_inner(),
            };
            attempts.push(password.to_vec());
            if password == self.secret.as_slice() {
                Ok(PasswordTest::Hit)
            } else {
                Ok(PasswordTest::Miss)
            }
        }
    }

    /// Opens [`FakeSession`]s and tracks how many were opened and tested.
    struct FakeFactory {
        secret: Vec<u8>,
        attempts: Arc<Mutex<Vec<Vec<u8>>>>,
        opens: AtomicUsize,
        fail_open: bool,
        delay: Duration,
    }

    impl FakeFactory {
        fn new(secret: &[u8]) -> Self {
            Self::with_delay(secret, Duration::ZERO)
        }

        fn with_delay(secret: &[u8], delay: Duration) -> Self {
            Self {
                secret: secret.to_vec(),
                attempts: Arc::new(Mutex::new(Vec::new())),
                opens: AtomicUsize::new(0),
                fail_open: false,
                delay,
            }
        }

        fn failing() -> Self {
            Self {
                fail_open: true,
                ..Self::new(SECRET)
            }
        }

        fn opens(&self) -> usize {
            self.opens.load(Ordering::SeqCst)
        }

        fn attempts(&self) -> Vec<Vec<u8>> {
            match self.attempts.lock() {
                Ok(attempts) => attempts.clone(),
                Err(poisoned) => poisoned.into_inner().clone(),
            }
        }
    }

    impl ArchiveSessionFactory for FakeFactory {
        fn open(&self) -> Result<Box<dyn ArchiveSession>> {
            self.opens.fetch_add(1, Ordering::SeqCst);
            if self.fail_open {
                return Err(AcxError::Unsupported("fake session failure".to_string()));
            }
            Ok(Box::new(FakeSession {
                info: fake_info(),
                secret: self.secret.clone(),
                attempts: Arc::clone(&self.attempts),
                delay: self.delay,
            }))
        }
    }

    fn fake_info() -> ArchiveInfo {
        ArchiveInfo {
            path: PathBuf::from("fake.zip"),
            format: ArchiveFormat::Zip,
            encryption: Encryption::ZipCrypto,
            selected: Some(0),
            whole_archive: false,
            header_encrypted: false,
            entries: Vec::new(),
        }
    }

    fn run_with(
        factory: &Arc<FakeFactory>,
        passwords: Vec<Vec<u8>>,
        threads: usize,
    ) -> Result<Option<Hit>> {
        let factory: Arc<FakeFactory> = Arc::clone(factory);
        run(factory, Arc::new(passwords), threads)
    }

    #[test]
    fn finds_the_correct_password() {
        let factory = Arc::new(FakeFactory::new(SECRET));
        let passwords = vec![b"wrong1".to_vec(), SECRET.to_vec(), b"wrong2".to_vec()];

        let hit = run_with(&factory, passwords, 1)
            .expect("scheduler run")
            .expect("correct password must be found");

        assert_eq!(hit.password, SECRET);
        assert_eq!(hit.tried, 2);
        assert_eq!(factory.opens(), 1);
    }

    #[test]
    fn returns_none_when_no_candidate_matches() {
        let factory = Arc::new(FakeFactory::new(SECRET));
        let passwords = vec![b"alpha".to_vec(), b"beta".to_vec()];

        let hit = run_with(&factory, passwords, 2).expect("scheduler run");

        assert!(hit.is_none());
        assert_eq!(factory.opens(), 2);
        assert_eq!(factory.attempts().len(), 2);
    }

    #[test]
    fn four_threads_visit_each_candidate_exactly_once() {
        let factory = Arc::new(FakeFactory::new(SECRET));
        let passwords: Vec<Vec<u8>> = (0..10_000)
            .map(|index| format!("wrong-{index}").into_bytes())
            .collect();

        let hit = run_with(&factory, passwords.clone(), 4).expect("scheduler run");

        assert!(hit.is_none());
        assert_eq!(factory.opens(), 4);

        let mut attempted = factory.attempts();
        let mut expected = passwords;
        attempted.sort_unstable();
        expected.sort_unstable();
        assert_eq!(attempted, expected);
    }

    #[test]
    fn empty_dictionary_returns_none_without_opening_sessions() {
        let factory = Arc::new(FakeFactory::new(SECRET));

        let hit = run_with(&factory, Vec::new(), 4).expect("scheduler run");

        assert!(hit.is_none());
        assert_eq!(factory.opens(), 0);
        assert!(factory.attempts().is_empty());
    }

    #[test]
    fn session_open_error_is_propagated() {
        let factory = Arc::new(FakeFactory::failing());
        let passwords = vec![b"alpha".to_vec(), b"beta".to_vec()];

        let error = run_with(&factory, passwords, 4).expect_err("session failure must surface");

        assert!(matches!(error, AcxError::Unsupported(_)));
        assert_eq!(factory.opens(), 4);
    }

    #[test]
    fn hit_does_not_advance_watermark_past_the_password() {
        let factory = Arc::new(FakeFactory::new(SECRET));
        let passwords = Arc::new(vec![
            b"wrong-0".to_vec(),
            SECRET.to_vec(),
            b"wrong-2".to_vec(),
        ]);
        let context = RunContext::new(passwords.len(), 0, 0, 1);
        let observer = Arc::clone(&context);
        let factory_dyn: Arc<dyn ArchiveSessionFactory> = factory;
        let outcome = run_with_context(factory_dyn, passwords, context).expect("run");
        assert!(matches!(outcome, RunOutcome::Found(_)));
        assert!(
            observer.snapshot().completed_through <= 1,
            "watermark must not pass the hit candidate"
        );
    }

    struct ShortSource {
        total: usize,
        yielded: bool,
    }

    impl CandidateSource for ShortSource {
        fn total(&self) -> usize {
            self.total
        }

        fn next_batch(&mut self, _max: usize) -> Result<Option<CandidateBatch>> {
            if self.yielded {
                return Ok(None);
            }
            self.yielded = true;
            Ok(Some(CandidateBatch {
                start_index: 0,
                candidates: vec![b"wrong".to_vec()],
            }))
        }
    }

    #[test]
    fn source_ending_before_total_is_an_error() {
        let factory: Arc<dyn ArchiveSessionFactory> = Arc::new(FakeFactory::new(SECRET));
        let context = RunContext::new(2, 0, 0, 1);
        let source = Box::new(ShortSource {
            total: 2,
            yielded: false,
        });
        let error = run_with_source(factory, source, context).expect_err("short source must fail");
        assert!(matches!(error, AcxError::Internal(_)));
    }

    #[test]
    fn pause_blocks_workers_and_resume_continues() {
        let factory = Arc::new(FakeFactory::with_delay(SECRET, Duration::from_millis(1)));
        let passwords: Arc<Vec<Vec<u8>>> = Arc::new(
            (0..2_000)
                .map(|index| {
                    if index == 1_500 {
                        SECRET.to_vec()
                    } else {
                        format!("wrong-{index}").into_bytes()
                    }
                })
                .collect(),
        );
        let context = RunContext::new(passwords.len(), 0, 0, 2);
        let control = context.control_arc();
        let factory_dyn: Arc<dyn ArchiveSessionFactory> = factory.clone();
        let handle =
            thread::spawn(move || run_with_context(factory_dyn, Arc::clone(&passwords), context));

        thread::sleep(Duration::from_millis(30));
        assert!(control.pause(), "pause request must be accepted");
        thread::sleep(Duration::from_millis(80));
        assert_eq!(control.state(), RunState::Paused);
        control.resume();
        let outcome = handle.join().expect("join").expect("run");
        assert!(matches!(&outcome, RunOutcome::Found(_)), "{outcome:?}");
    }

    #[test]
    fn stop_returns_a_safe_watermark() {
        let factory = Arc::new(FakeFactory::with_delay(SECRET, Duration::from_millis(1)));
        let passwords: Vec<Vec<u8>> = (0..2_000)
            .map(|index| format!("wrong-{index}").into_bytes())
            .collect();
        let context = RunContext::new(passwords.len(), 0, 0, 2);
        let control = context.control_arc();
        let factory_dyn: Arc<dyn ArchiveSessionFactory> = factory.clone();
        let handle =
            thread::spawn(move || run_with_context(factory_dyn, Arc::new(passwords), context));

        thread::sleep(Duration::from_millis(30));
        control.stop();
        let outcome = handle.join().expect("join").expect("run");
        let progress = match outcome {
            RunOutcome::Stopped(progress) => progress,
            other => panic!("expected stopped, got {other:?}"),
        };
        assert!(progress.completed_through < progress.total);
        assert!(progress.tried >= progress.completed_through);
    }

    #[test]
    fn stop_watermark_stays_inside_the_4096_candidate_window() {
        let factory = Arc::new(FakeFactory::with_delay(SECRET, Duration::from_millis(1)));
        let passwords: Vec<Vec<u8>> = (0..50_000)
            .map(|index| format!("wrong-{index}").into_bytes())
            .collect();
        let context = RunContext::new(passwords.len(), 0, 0, 8);
        let control = context.control_arc();
        let factory_dyn: Arc<dyn ArchiveSessionFactory> = factory;
        let handle =
            thread::spawn(move || run_with_context(factory_dyn, Arc::new(passwords), context));

        thread::sleep(Duration::from_millis(60));
        control.stop();
        let outcome = handle.join().expect("join").expect("run");
        let progress = match outcome {
            RunOutcome::Stopped(progress) => progress,
            other => panic!("expected stopped, got {other:?}"),
        };
        assert!(
            progress.tried - progress.completed_through <= 4096,
            "hard-kill replay window exceeded: tried {} completed {}",
            progress.tried,
            progress.completed_through
        );
    }
}
