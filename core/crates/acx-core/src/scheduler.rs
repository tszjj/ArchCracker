// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

//! Multi-threaded dictionary scheduler.
//!
//! The main thread acts as the producer: it slices the candidate list into
//! fixed-size index batches and hands them to the workers through a bounded
//! `crossbeam-channel`. Every worker opens exactly one archive session and
//! tests the candidates of the batches it receives until a hit is reported,
//! an error occurs, or the candidate list is exhausted.
//!
//! A shared [`AtomicBool`] stop flag keeps the producer from queueing more work
//! after a hit/error, and lets workers skip the rest of an in-flight batch.

use crate::archive::{ArchiveSessionFactory, PasswordTest};
use crate::error::{AcxError, Result};
use crossbeam_channel::{bounded, Receiver};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

/// Number of candidate indices handed to a worker in one batch.
const BATCH_SIZE: usize = 4096;

/// Upper bound for worker threads; extra threads only add open sessions.
const MAX_THREADS: usize = 256;

/// A verified password found by the scheduler.
#[derive(Debug, Clone)]
pub struct Hit {
    pub password: Vec<u8>,
    /// Number of candidates attempted when the hit was recorded.
    pub tried: u64,
}

/// Run a dictionary attack over `passwords` using `threads` workers.
///
/// Returns `Ok(Some(hit))` as soon as a worker reports a verified hit,
/// `Ok(None)` when every candidate missed, and `Err` for the first worker
/// error (session open or candidate test failure). An empty candidate list
/// returns `Ok(None)` without opening any sessions. `threads` is clamped to
/// `1..=256`.
pub fn run(
    factory: Arc<dyn ArchiveSessionFactory>,
    passwords: Arc<Vec<Vec<u8>>>,
    threads: usize,
) -> Result<Option<Hit>> {
    if passwords.is_empty() {
        return Ok(None);
    }

    let threads = threads.clamp(1, MAX_THREADS);
    let total = passwords.len();
    let (batch_tx, batch_rx) = bounded::<(usize, usize)>(threads * 2);

    let stop = Arc::new(AtomicBool::new(false));
    let tried = Arc::new(AtomicU64::new(0));
    let hit: Arc<Mutex<Option<Hit>>> = Arc::new(Mutex::new(None));
    let mut first_error: Option<AcxError> = None;

    thread::scope(|scope| {
        let mut handles = Vec::with_capacity(threads);
        for _ in 0..threads {
            let batches: Receiver<(usize, usize)> = batch_rx.clone();
            let factory = Arc::clone(&factory);
            let passwords = Arc::clone(&passwords);
            let stop = Arc::clone(&stop);
            let tried = Arc::clone(&tried);
            let hit = Arc::clone(&hit);

            handles.push(scope.spawn(move || -> Result<()> {
                let result =
                    worker_loop(factory.as_ref(), &passwords, batches, &stop, &tried, &hit);
                // A failing worker must wake the producer and its peers;
                // otherwise the producer could keep filling the queue while
                // the remaining workers wait for a batch nobody will take.
                if result.is_err() {
                    stop.store(true, Ordering::SeqCst);
                }
                result
            }));
        }

        // The producer must own no receiver while sending: once every worker
        // has exited, `send` has to observe the disconnect instead of blocking
        // forever on a full queue.
        drop(batch_rx);

        // Producer: index batches, stopping early after a hit/error or when
        // all workers are gone.
        let mut start = 0;
        while start < total && !stop.load(Ordering::SeqCst) {
            let end = (start + BATCH_SIZE).min(total);
            if batch_tx.send((start, end)).is_err() {
                break;
            }
            start = end;
        }
        drop(batch_tx);

        // Join in spawn order; the first error encountered is the one reported.
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

    if let Some(error) = first_error {
        return Err(error);
    }

    let found = match hit.lock() {
        Ok(mut slot) => slot.take(),
        Err(poisoned) => poisoned.into_inner().take(),
    };
    Ok(found)
}

/// Consume batches until the list is exhausted, a hit is found, or stop is set.
///
/// The session is opened once per worker, before any batch is processed, so a
/// preflight/session failure aborts the whole attack instead of being retried
/// for every batch.
fn worker_loop(
    factory: &dyn ArchiveSessionFactory,
    passwords: &[Vec<u8>],
    batches: Receiver<(usize, usize)>,
    stop: &AtomicBool,
    tried: &AtomicU64,
    hit: &Mutex<Option<Hit>>,
) -> Result<()> {
    let mut session = factory.open()?;

    while !stop.load(Ordering::SeqCst) {
        let (start, end) = match batches.recv() {
            Ok(batch) => batch,
            // Producer finished (normal end) or all senders were dropped.
            Err(_) => break,
        };

        for password in &passwords[start..end] {
            if stop.load(Ordering::SeqCst) {
                break;
            }

            if session.test_password(password)? == PasswordTest::Hit {
                // Count this candidate before publishing the hit so `tried`
                // reflects an attempt, not just the misses before it.
                let attempt = tried.fetch_add(1, Ordering::SeqCst) + 1;
                stop.store(true, Ordering::SeqCst);
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
                return Ok(());
            }
            tried.fetch_add(1, Ordering::SeqCst);
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
    }

    impl ArchiveSession for FakeSession {
        fn info(&self) -> &ArchiveInfo {
            &self.info
        }

        fn test_password(&mut self, password: &[u8]) -> Result<PasswordTest> {
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
    }

    impl FakeFactory {
        fn new(secret: &[u8]) -> Self {
            Self {
                secret: secret.to_vec(),
                attempts: Arc::new(Mutex::new(Vec::new())),
                opens: AtomicUsize::new(0),
                fail_open: false,
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
        // `run` takes `Arc<dyn ArchiveSessionFactory>`; clone the concrete
        // `Arc<FakeFactory>` first and let unsizing coerce it at the call.
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
        // One worker and one batch: `wrong1` misses, `SECRET` hits.
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
        // More than two full batches so several rounds of work are dispatched.
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
        // Every candidate appears exactly once: no lost or duplicated indices.
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
}
