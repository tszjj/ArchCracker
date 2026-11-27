// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

//! One reusable attack job: preflight, candidate source, checkpoint, scheduler.
//!
//! The single-task CLI and the batch runner both call [`run_job`], so archive
//! validation, checkpoint/resume, stop propagation, and result classification
//! exist once. The module deliberately does not print; callers use a
//! [`JobObserver`] for the pre-attack summary and render the final
//! [`JobReport`] themselves.

use crate::archive::{
    self, ArchiveFormat, ArchiveInfo, ArchiveSessionFactory, ArchiveSource, PasswordTest,
    RarFactory, SevenZFactory, ZipFactory,
};
use crate::candidates::{
    BruteSet, CandidateSource, DictionaryStream, HybridSet, MaskSet, MAX_BATCH_BYTES,
};
use crate::checkpoint::{
    ArchiveFingerprint, AttackFingerprint, Checkpoint, CheckpointStore, FileFingerprint,
};
use crate::encoding::{
    EncodingCounters, EncodingFactory, EncodingPlan, EncodingSelection, EncodingStats,
};
use crate::error::{AcxError, Result};
use crate::estimate::{estimate_space, SpaceEstimate, SpaceInput};
use crate::scheduler::{self, RunContext, RunControl, RunOutcome};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Maximum worker threads accepted by a job.
pub const MAX_JOB_THREADS: usize = 256;

#[derive(Debug, Clone)]
pub enum AttackConfig {
    Dictionary {
        dictionary: PathBuf,
    },
    Mask {
        masks: Vec<String>,
        custom: [Option<String>; 4],
    },
    Brute {
        charset: String,
        min_len: usize,
        max_len: usize,
        custom: [Option<String>; 4],
    },
    Hybrid {
        dictionary: PathBuf,
        rules: Vec<String>,
        prefix_mask: Option<String>,
        suffix_mask: Option<String>,
        custom: [Option<String>; 4],
    },
}

#[derive(Debug, Clone)]
pub struct JobSpec {
    pub id: String,
    pub archive: PathBuf,
    pub attack: AttackConfig,
    pub threads: usize,
    pub checkpoint: PathBuf,
    pub resume: bool,
    pub encoding: EncodingSelection,
    pub strict: bool,
    pub rar_no_fast_reject: bool,
    pub report_stats: bool,
}

#[derive(Debug, Clone)]
pub struct JobEstimate {
    pub info: ArchiveInfo,
    pub total: u128,
    pub fits_usize: bool,
    pub space: SpaceEstimate,
    pub detail: EstimateDetail,
    pub warnings: Vec<String>,
    /// Maximum number of encoding variants a single candidate may try.
    pub encoding_variants: usize,
}

#[derive(Debug, Clone)]
pub enum EstimateDetail {
    Dictionary,
    Mask {
        masks: Vec<String>,
        per_mask: Vec<u128>,
    },
    Brute {
        charset: String,
        min_len: usize,
        max_len: usize,
        per_len: Vec<u128>,
    },
    Hybrid {
        dict_lines: usize,
        variants_per_line: u128,
    },
}

/// Pre-attack information handed to the caller for printing.
#[derive(Debug, Clone)]
pub struct JobPreview {
    pub estimate: JobEstimate,
    pub checkpoint: PathBuf,
    pub start_index: usize,
    pub tried: u64,
    pub resumed: bool,
}

/// Optional presentation hook. The default implementation prints nothing.
pub trait JobObserver {
    /// Called as soon as the archive preflight succeeds, before any attack
    /// validation error can occur.
    fn archive(&mut self, _info: &ArchiveInfo) {}
    fn prepared(&mut self, _preview: &JobPreview) {}
}

pub struct SilentObserver;

impl JobObserver for SilentObserver {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobStatus {
    Found,
    NotFound,
    Stopped,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct JobStats {
    pub encoding: EncodingStats,
    pub fast_rejected: u64,
    pub external_confirmed: u64,
}

#[derive(Debug)]
pub struct JobReport {
    pub status: JobStatus,
    pub password: Option<Vec<u8>>,
    pub reused: bool,
    pub tried: u64,
    pub completed_through: u64,
    pub total: u64,
    pub elapsed: Duration,
    pub checkpoint: PathBuf,
    pub error: Option<AcxError>,
    pub warnings: Vec<String>,
    pub stats: JobStats,
}

impl JobReport {
    pub fn failed(checkpoint: PathBuf, error: AcxError, elapsed: Duration) -> Self {
        Self {
            status: JobStatus::Failed,
            password: None,
            reused: false,
            tried: 0,
            completed_through: 0,
            total: 0,
            elapsed,
            checkpoint,
            error: Some(error),
            warnings: Vec::new(),
            stats: JobStats::default(),
        }
    }

    pub fn cancelled(checkpoint: PathBuf) -> Self {
        Self {
            status: JobStatus::Cancelled,
            password: None,
            reused: false,
            tried: 0,
            completed_through: 0,
            total: 0,
            elapsed: Duration::ZERO,
            checkpoint,
            error: None,
            warnings: Vec::new(),
            stats: JobStats::default(),
        }
    }
}

fn dictionary_error(error: AcxError) -> AcxError {
    match error {
        AcxError::Io(io) => AcxError::Dictionary(format!("cannot read dictionary: {io}")),
        other => other,
    }
}

/// Validate configuration and input paths without starting an attack.
///
/// Archive format/corruption is deliberately left to [`run_job`]: a bad archive
/// must fail only that batch task, not abort manifest-wide validation.
pub fn validate_job(spec: &JobSpec) -> Result<()> {
    if spec.threads == 0 || spec.threads > MAX_JOB_THREADS {
        return Err(AcxError::Attack(format!(
            "job `{}` threads {} is outside 1..={MAX_JOB_THREADS}",
            spec.id, spec.threads
        )));
    }
    let metadata = std::fs::metadata(&spec.archive)?;
    if !metadata.is_file() {
        return Err(AcxError::Attack(format!(
            "archive path `{}` is not a file",
            spec.archive.display()
        )));
    }
    std::fs::File::open(&spec.archive)?;
    // If the magic is readable, reject format-inapplicable encoding variants
    // before any task starts. A corrupt archive is left to run_job so one bad
    // package cannot abort the whole batch.
    if let Ok(format) = archive::detect_format(&spec.archive) {
        spec.encoding.resolve(format)?;
    }
    match &spec.attack {
        AttackConfig::Dictionary { dictionary } => {
            let stream = DictionaryStream::open(dictionary, 0).map_err(dictionary_error)?;
            if stream.total() == 0 {
                return Err(AcxError::Attack(format!(
                    "job `{}` dictionary contains no candidates",
                    spec.id
                )));
            }
        }
        AttackConfig::Mask { masks, custom } => {
            let set = MaskSet::parse(masks, custom)?;
            let estimate = set.estimate(spec.threads);
            if !estimate.fits_usize {
                return Err(AcxError::Attack(format!(
                    "job `{}` mask keyspace {} cannot be executed with the current usize index limit",
                    spec.id, estimate.keyspace
                )));
            }
            if estimate.keyspace == 0 {
                return Err(AcxError::Attack(format!(
                    "job `{}` mask contains no candidates",
                    spec.id
                )));
            }
        }
        AttackConfig::Brute {
            charset,
            min_len,
            max_len,
            custom,
        } => {
            let set = BruteSet::parse(charset, custom, *min_len, *max_len)?;
            let estimate = set.estimate(spec.threads);
            if !estimate.fits_usize {
                return Err(AcxError::Attack(format!(
                    "job `{}` brute keyspace {} cannot be executed with the current usize index limit",
                    spec.id, estimate.keyspace
                )));
            }
        }
        AttackConfig::Hybrid {
            dictionary,
            rules,
            prefix_mask,
            suffix_mask,
            custom,
        } => {
            let set = HybridSet::parse(
                dictionary,
                rules,
                prefix_mask.as_deref(),
                suffix_mask.as_deref(),
                custom,
            )
            .map_err(dictionary_error)?;
            let estimate = set.estimate(spec.threads);
            if !estimate.fits_usize {
                return Err(AcxError::Attack(format!(
                    "job `{}` hybrid total {} cannot be executed with the current usize index limit",
                    spec.id, estimate.total
                )));
            }
            if estimate.total == 0 {
                return Err(AcxError::Attack(format!(
                    "job `{}` dictionary contains no candidates",
                    spec.id
                )));
            }
        }
    }
    Ok(())
}

/// Parse the attack and compute keyspace/space without touching checkpoints.
pub fn estimate_job(spec: &JobSpec) -> Result<JobEstimate> {
    let info = archive::preflight(&spec.archive)?;
    estimate_attack(spec, &info)
}

fn estimate_attack(spec: &JobSpec, info: &ArchiveInfo) -> Result<JobEstimate> {
    let encoding = spec.encoding.resolve(info.format)?;
    let encoding_variants = encoding.max_variants();
    match &spec.attack {
        AttackConfig::Dictionary { dictionary } => {
            let stream = DictionaryStream::open(dictionary, 0)?;
            let total = stream.total() as u128;
            let space = dictionary_space(total, stream.max_line_bytes(), spec.threads);
            Ok(JobEstimate {
                info: info.clone(),
                total,
                fits_usize: true,
                space,
                detail: EstimateDetail::Dictionary,
                warnings: Vec::new(),
                encoding_variants,
            })
        }
        AttackConfig::Mask { masks, custom } => {
            let set = MaskSet::parse(masks, custom)?;
            let estimate = set.estimate(spec.threads);
            Ok(JobEstimate {
                info: info.clone(),
                total: estimate.keyspace,
                fits_usize: estimate.fits_usize,
                space: estimate.space,
                detail: EstimateDetail::Mask {
                    masks: masks.clone(),
                    per_mask: estimate.per_mask,
                },
                warnings: estimate
                    .warnings
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect(),
                encoding_variants,
            })
        }
        AttackConfig::Brute {
            charset,
            min_len,
            max_len,
            custom,
        } => {
            let set = BruteSet::parse(charset, custom, *min_len, *max_len)?;
            let estimate = set.estimate(spec.threads);
            Ok(JobEstimate {
                info: info.clone(),
                total: estimate.keyspace,
                fits_usize: estimate.fits_usize,
                space: estimate.space,
                detail: EstimateDetail::Brute {
                    charset: charset.clone(),
                    min_len: *min_len,
                    max_len: *max_len,
                    per_len: estimate.per_len,
                },
                warnings: estimate
                    .warnings
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect(),
                encoding_variants,
            })
        }
        AttackConfig::Hybrid {
            dictionary,
            rules,
            prefix_mask,
            suffix_mask,
            custom,
        } => {
            let set = HybridSet::parse(
                dictionary,
                rules,
                prefix_mask.as_deref(),
                suffix_mask.as_deref(),
                custom,
            )?;
            let estimate = set.estimate(spec.threads);
            Ok(JobEstimate {
                info: info.clone(),
                total: estimate.total,
                fits_usize: estimate.fits_usize,
                space: estimate.space,
                detail: EstimateDetail::Hybrid {
                    dict_lines: estimate.dict_lines,
                    variants_per_line: estimate.variants_per_line,
                },
                warnings: estimate
                    .warnings
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect(),
                encoding_variants,
            })
        }
    }
}

fn dictionary_space(total: u128, max_line_bytes: usize, threads: usize) -> SpaceEstimate {
    estimate_space(&SpaceInput {
        total,
        threads,
        max_candidate_bytes: max_line_bytes as u128,
        batch_bytes_cap: Some(MAX_BATCH_BYTES as u128),
        source_bytes: 2 * max_line_bytes as u128 + 5 * 64 * 1024,
    })
}

struct PreparedAttack {
    source: Box<dyn CandidateSource>,
    total: usize,
    estimate: JobEstimate,
    dictionary: Option<FileFingerprint>,
    attack: AttackFingerprint,
    encoding: EncodingPlan,
}

fn finalize_attack(
    base: AttackFingerprint,
    mode: &str,
    spec: &JobSpec,
    encoding: &EncodingPlan,
) -> AttackFingerprint {
    if spec.encoding.is_auto() && !spec.strict && !spec.rar_no_fast_reject {
        return base;
    }
    let material = format!(
        "{}\nencoding={}\nstrict={}\nrar_no_fast_reject={}",
        base.signature,
        encoding.signature_label(),
        spec.strict,
        spec.rar_no_fast_reject
    );
    AttackFingerprint::new(mode, &hex_sha256(material.as_bytes()))
}

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn prepare_attack(
    spec: &JobSpec,
    info: &ArchiveInfo,
    start_index: usize,
) -> Result<PreparedAttack> {
    let encoding = spec.encoding.resolve(info.format)?;
    let encoding_variants = encoding.max_variants();
    match &spec.attack {
        AttackConfig::Dictionary { dictionary } => {
            let fingerprint = FileFingerprint::from_path(dictionary).map_err(dictionary_error)?;
            let stream =
                DictionaryStream::open(dictionary, start_index).map_err(dictionary_error)?;
            let total = stream.total();
            let estimate = JobEstimate {
                info: info.clone(),
                total: total as u128,
                fits_usize: true,
                space: dictionary_space(total as u128, stream.max_line_bytes(), spec.threads),
                detail: EstimateDetail::Dictionary,
                warnings: Vec::new(),
                encoding_variants,
            };
            let attack = finalize_attack(AttackFingerprint::dictionary(), "dict", spec, &encoding);
            Ok(PreparedAttack {
                source: Box::new(stream),
                total,
                estimate,
                dictionary: Some(fingerprint),
                attack,
                encoding,
            })
        }
        AttackConfig::Mask { masks, custom } => {
            let set = MaskSet::parse(masks, custom)?;
            let estimate = set.estimate(spec.threads);
            if !estimate.fits_usize {
                return Err(AcxError::Attack(format!(
                    "mask keyspace {} cannot be executed with the current usize index limit",
                    estimate.keyspace
                )));
            }
            let attack = finalize_attack(
                AttackFingerprint::new("mask", set.signature()),
                "mask",
                spec,
                &encoding,
            );
            let source = set.into_source(start_index)?;
            let total = source.total();
            Ok(PreparedAttack {
                source: Box::new(source),
                total,
                estimate: job_estimate_from_mask(info, estimate, masks, encoding_variants),
                dictionary: None,
                attack,
                encoding,
            })
        }
        AttackConfig::Brute {
            charset,
            min_len,
            max_len,
            custom,
        } => {
            let set = BruteSet::parse(charset, custom, *min_len, *max_len)?;
            let estimate = set.estimate(spec.threads);
            if !estimate.fits_usize {
                return Err(AcxError::Attack(format!(
                    "brute keyspace {} cannot be executed with the current usize index limit",
                    estimate.keyspace
                )));
            }
            let attack = finalize_attack(
                AttackFingerprint::new("brute", set.signature()),
                "brute",
                spec,
                &encoding,
            );
            let source = set.into_source(start_index)?;
            let total = source.total();
            Ok(PreparedAttack {
                source: Box::new(source),
                total,
                estimate: job_estimate_from_brute(
                    info,
                    estimate,
                    charset,
                    *min_len,
                    *max_len,
                    encoding_variants,
                ),
                dictionary: None,
                attack,
                encoding,
            })
        }
        AttackConfig::Hybrid {
            dictionary,
            rules,
            prefix_mask,
            suffix_mask,
            custom,
        } => {
            let fingerprint = FileFingerprint::from_path(dictionary).map_err(dictionary_error)?;
            let set = HybridSet::parse(
                dictionary,
                rules,
                prefix_mask.as_deref(),
                suffix_mask.as_deref(),
                custom,
            )
            .map_err(dictionary_error)?;
            let estimate = set.estimate(spec.threads);
            if !estimate.fits_usize {
                return Err(AcxError::Attack(format!(
                    "hybrid total {} cannot be executed with the current usize index limit",
                    estimate.total
                )));
            }
            let attack = finalize_attack(
                AttackFingerprint::new("hybrid", set.signature()),
                "hybrid",
                spec,
                &encoding,
            );
            let source = set.into_source(start_index)?;
            let total = source.total();
            Ok(PreparedAttack {
                source: Box::new(source),
                total,
                estimate: job_estimate_from_hybrid(info, estimate, encoding_variants),
                dictionary: Some(fingerprint),
                attack,
                encoding,
            })
        }
    }
}

fn job_estimate_from_mask(
    info: &ArchiveInfo,
    estimate: crate::candidates::MaskEstimate,
    masks: &[String],
    encoding_variants: usize,
) -> JobEstimate {
    JobEstimate {
        info: info.clone(),
        total: estimate.keyspace,
        fits_usize: estimate.fits_usize,
        space: estimate.space,
        detail: EstimateDetail::Mask {
            masks: masks.to_vec(),
            per_mask: estimate.per_mask,
        },
        warnings: estimate
            .warnings
            .iter()
            .map(std::string::ToString::to_string)
            .collect(),
        encoding_variants,
    }
}

fn job_estimate_from_brute(
    info: &ArchiveInfo,
    estimate: crate::candidates::BruteEstimate,
    charset: &str,
    min_len: usize,
    max_len: usize,
    encoding_variants: usize,
) -> JobEstimate {
    JobEstimate {
        info: info.clone(),
        total: estimate.keyspace,
        fits_usize: estimate.fits_usize,
        space: estimate.space,
        detail: EstimateDetail::Brute {
            charset: charset.to_string(),
            min_len,
            max_len,
            per_len: estimate.per_len,
        },
        warnings: estimate
            .warnings
            .iter()
            .map(std::string::ToString::to_string)
            .collect(),
        encoding_variants,
    }
}

fn job_estimate_from_hybrid(
    info: &ArchiveInfo,
    estimate: crate::candidates::HybridEstimate,
    encoding_variants: usize,
) -> JobEstimate {
    JobEstimate {
        info: info.clone(),
        total: estimate.total,
        fits_usize: estimate.fits_usize,
        space: estimate.space,
        detail: EstimateDetail::Hybrid {
            dict_lines: estimate.dict_lines,
            variants_per_line: estimate.variants_per_line,
        },
        warnings: estimate
            .warnings
            .iter()
            .map(std::string::ToString::to_string)
            .collect(),
        encoding_variants,
    }
}

fn job_stats(
    counters: &EncodingCounters,
    factory: &Arc<dyn ArchiveSessionFactory>,
    baseline: crate::archive::ArchiveStats,
) -> JobStats {
    let archive = factory.stats();
    let mut encoding = counters.snapshot();
    encoding.variants_skipped += archive
        .encoding_skipped
        .saturating_sub(baseline.encoding_skipped);
    JobStats {
        encoding,
        fast_rejected: archive.fast_rejected.saturating_sub(baseline.fast_rejected),
        external_confirmed: archive
            .external_confirmed
            .saturating_sub(baseline.external_confirmed),
    }
}

fn build_factory(
    info: &ArchiveInfo,
    archive: &Path,
    spec: &JobSpec,
) -> Result<Arc<dyn ArchiveSessionFactory>> {
    match info.format {
        ArchiveFormat::Zip => Ok(Arc::new(ZipFactory {
            path: archive.to_path_buf(),
        })),
        ArchiveFormat::SevenZ => {
            let factory = SevenZFactory::from_info(archive.to_path_buf(), info.clone())?
                .with_strict(spec.strict);
            Ok(Arc::new(factory))
        }
        ArchiveFormat::Rar4 | ArchiveFormat::Rar5 => {
            let factory = RarFactory::from_info(archive.to_path_buf(), info.clone())?
                .with_fast_filter(!spec.strict && !spec.rar_no_fast_reject);
            Ok(Arc::new(factory))
        }
    }
}

/// Run one job to completion, a stop request, or a failure.
///
/// `prepass` contains already-confirmed passwords (batch reuse). It is tried
/// before the checkpoint is created and never affects the candidate index or
/// completion watermark.
pub fn run_job(
    spec: &JobSpec,
    control: Arc<RunControl>,
    prepass: &[Vec<u8>],
    observer: &mut dyn JobObserver,
) -> Result<JobReport> {
    let started = Instant::now();
    let info = archive::preflight(&spec.archive)?;
    observer.archive(&info);
    if !info.has_verification_target() {
        return Err(AcxError::Unsupported(
            "archive is not encrypted or has no file entries".to_string(),
        ));
    }
    let archive_factory = build_factory(&info, &spec.archive, spec)?;
    let source = ArchiveSource::resolve(&spec.archive)?;
    let archive_fingerprint = ArchiveFingerprint::from_source(&source)?;

    let store = CheckpointStore::new(spec.checkpoint.clone());
    if spec.resume {
        store.clear_lock()?;
    }
    let _lock = store.lock()?;

    let (start_index, tried, loaded) = if spec.resume {
        let checkpoint = store.load()?;
        (
            usize::try_from(checkpoint.completed_through).map_err(|_| {
                AcxError::Checkpoint("checkpoint watermark is too large".to_string())
            })?,
            checkpoint.tried,
            Some(checkpoint),
        )
    } else {
        (0, 0, None)
    };

    let prepared = prepare_attack(spec, &info, start_index)?;
    if let Some(checkpoint) = loaded.as_ref() {
        checkpoint.validate(
            &archive_fingerprint,
            prepared.dictionary.as_ref(),
            &prepared.attack,
            prepared.total as u64,
        )?;
    }

    let prepass_counter = Arc::new(EncodingCounters::default());
    let prepass_factory: Arc<dyn ArchiveSessionFactory> = Arc::new(EncodingFactory::new(
        Arc::clone(&archive_factory),
        prepared.encoding.clone(),
        Arc::clone(&prepass_counter),
    ));
    let scheduler_counters = Arc::new(EncodingCounters::default());
    let factory: Arc<dyn ArchiveSessionFactory> = Arc::new(EncodingFactory::new(
        archive_factory,
        prepared.encoding.clone(),
        Arc::clone(&scheduler_counters),
    ));
    let stats_factory = Arc::clone(&factory);

    observer.prepared(&JobPreview {
        estimate: prepared.estimate.clone(),
        checkpoint: spec.checkpoint.clone(),
        start_index,
        tried,
        resumed: loaded.is_some(),
    });

    let mut warnings = Vec::new();
    if !prepass.is_empty() {
        let mut session = prepass_factory.open()?;
        session.set_cancel_token(control.cancel_token());
        for password in prepass {
            if control.is_stopping() {
                break;
            }
            match session.test_password(password)? {
                PasswordTest::Hit => {
                    if let Err(error) = store.remove() {
                        warnings.push(format!("could not remove checkpoint: {error}"));
                    }
                    return Ok(JobReport {
                        status: JobStatus::Found,
                        password: Some(password.clone()),
                        reused: true,
                        tried: 0,
                        completed_through: start_index as u64,
                        total: prepared.total as u64,
                        elapsed: started.elapsed(),
                        checkpoint: spec.checkpoint.clone(),
                        error: None,
                        warnings,
                        stats: JobStats::default(),
                    });
                }
                PasswordTest::Miss => {}
            }
        }
    }

    let archive_baseline = stats_factory.stats();

    if prepared.total == 0 {
        return Err(AcxError::Attack(
            "attack contains no candidates".to_string(),
        ));
    }

    if start_index >= prepared.total {
        if let Err(error) = store.remove() {
            warnings.push(format!("could not remove checkpoint: {error}"));
        }
        return Ok(JobReport {
            status: JobStatus::NotFound,
            password: None,
            reused: false,
            tried,
            completed_through: start_index as u64,
            total: prepared.total as u64,
            elapsed: started.elapsed(),
            checkpoint: spec.checkpoint.clone(),
            error: None,
            warnings,
            stats: job_stats(&scheduler_counters, &stats_factory, archive_baseline),
        });
    }

    let initial = Checkpoint::new(
        archive_fingerprint.clone(),
        prepared.dictionary.clone(),
        prepared.attack.clone(),
        spec.threads.clamp(1, MAX_JOB_THREADS),
        start_index as u64,
        tried,
        prepared.total as u64,
    );
    store.save(&initial)?;

    let context = RunContext::with_control(
        prepared.total,
        start_index,
        tried,
        spec.threads,
        Arc::clone(&control),
    );
    let finished = Arc::new(AtomicBool::new(false));
    let monitor_error = Arc::new(Mutex::new(None::<String>));
    let monitor = start_checkpoint_monitor(
        store.clone(),
        Arc::clone(&context),
        archive_fingerprint.clone(),
        prepared.dictionary.clone(),
        prepared.attack.clone(),
        Arc::clone(&finished),
        Arc::clone(&monitor_error),
    );

    let outcome = scheduler::run_with_source(factory, prepared.source, Arc::clone(&context));
    finished.store(true, Ordering::SeqCst);
    let _ = monitor.join();
    if let Some(error) = monitor_error
        .lock()
        .ok()
        .and_then(|slot| slot.as_ref().cloned())
    {
        warnings.push(format!("checkpoint monitor: {error}"));
    }

    let progress = context.snapshot();
    let total = progress.total;
    let checkpoint_path = spec.checkpoint.clone();
    let elapsed = started.elapsed();

    match outcome {
        Ok(RunOutcome::Found(hit)) => {
            if let Err(error) = store.remove() {
                warnings.push(format!("could not remove checkpoint: {error}"));
            }
            Ok(JobReport {
                status: JobStatus::Found,
                password: Some(hit.password),
                reused: false,
                tried: hit.tried,
                completed_through: progress.completed_through,
                total,
                elapsed,
                checkpoint: checkpoint_path,
                error: None,
                warnings,
                stats: job_stats(&scheduler_counters, &stats_factory, archive_baseline),
            })
        }
        Ok(RunOutcome::Exhausted) => {
            if let Err(error) = store.remove() {
                warnings.push(format!("could not remove checkpoint: {error}"));
            }
            Ok(JobReport {
                status: JobStatus::NotFound,
                password: None,
                reused: false,
                tried: progress.tried,
                completed_through: total,
                total,
                elapsed,
                checkpoint: checkpoint_path,
                error: None,
                warnings,
                stats: job_stats(&scheduler_counters, &stats_factory, archive_baseline),
            })
        }
        Ok(RunOutcome::Stopped(progress)) => {
            let checkpoint = Checkpoint::new(
                archive_fingerprint,
                prepared.dictionary,
                prepared.attack,
                context.threads(),
                progress.completed_through,
                progress.tried,
                progress.total,
            );
            store.save(&checkpoint)?;
            Ok(JobReport {
                status: JobStatus::Stopped,
                password: None,
                reused: false,
                tried: progress.tried,
                completed_through: progress.completed_through,
                total,
                elapsed,
                checkpoint: checkpoint_path,
                error: None,
                warnings,
                stats: job_stats(&scheduler_counters, &stats_factory, archive_baseline),
            })
        }
        Err(error) => {
            if progress.tried > 0 {
                let checkpoint = Checkpoint::new(
                    archive_fingerprint,
                    prepared.dictionary,
                    prepared.attack,
                    context.threads(),
                    progress.completed_through,
                    progress.tried,
                    progress.total,
                );
                if let Err(save_error) = store.save(&checkpoint) {
                    warnings.push(format!("could not save checkpoint: {save_error}"));
                }
            }
            Ok(JobReport {
                status: JobStatus::Failed,
                password: None,
                reused: false,
                tried: progress.tried,
                completed_through: progress.completed_through,
                total,
                elapsed,
                checkpoint: checkpoint_path,
                error: Some(error),
                warnings,
                stats: job_stats(&scheduler_counters, &stats_factory, archive_baseline),
            })
        }
    }
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
        if finished.load(Ordering::SeqCst) || context.has_found() {
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
