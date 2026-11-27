// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

//! Batch job manifests, validation, and bounded-parallel orchestration.
//!
//! A batch is a list of independent [`JobSpec`]s. Each task owns its checkpoint
//! file; a failure or stop affects only that task. Confirmed passwords can be
//! reused inside the batch only when the manifest/CLI explicitly enables it,
//! and the cache is memory-only.

use crate::error::{AcxError, Result};
use crate::job::{
    estimate_job, run_job, validate_job, AttackConfig, JobEstimate, JobReport, JobSpec, JobStatus,
    SilentObserver, MAX_JOB_THREADS,
};
use crate::scheduler::RunControl;
use serde::Deserialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

const DEFAULT_MAX_PARALLEL: usize = 1;
const DEFAULT_THREADS: usize = 1;
const MAX_BATCH_PARALLEL: usize = 256;
const MAX_ID_BYTES: usize = 64;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    #[serde(default = "default_max_parallel")]
    max_parallel: usize,
    #[serde(default)]
    reuse_found: bool,
    checkpoint_root: Option<PathBuf>,
    jobs: Vec<JobEntry>,
}

fn default_max_parallel() -> usize {
    DEFAULT_MAX_PARALLEL
}

fn default_threads() -> usize {
    DEFAULT_THREADS
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct JobEntry {
    id: String,
    archive: PathBuf,
    #[serde(default = "default_threads")]
    threads: usize,
    mode: String,
    dictionary: Option<PathBuf>,
    masks: Option<Vec<String>>,
    charset: Option<String>,
    min_len: Option<usize>,
    max_len: Option<usize>,
    rules: Option<Vec<String>>,
    prefix_mask: Option<String>,
    suffix_mask: Option<String>,
    custom_charset1: Option<String>,
    custom_charset2: Option<String>,
    custom_charset3: Option<String>,
    custom_charset4: Option<String>,
    reuse_found: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct BatchJob {
    pub id: String,
    pub spec: JobSpec,
    /// `None` inherits the manifest/CLI-wide setting.
    pub reuse_found: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct BatchConfig {
    pub max_parallel: usize,
    pub reuse_found: bool,
    pub checkpoint_root: PathBuf,
    pub jobs: Vec<BatchJob>,
    pub warnings: Vec<String>,
}

#[derive(Debug)]
pub struct BatchPreview {
    pub id: String,
    pub result: Result<JobEstimate>,
}

#[derive(Debug)]
pub struct BatchReport {
    pub tasks: Vec<BatchTaskReport>,
    pub stopped: bool,
    pub fail_fast_triggered: bool,
}

#[derive(Debug)]
pub struct BatchTaskReport {
    pub id: String,
    pub report: JobReport,
}

impl BatchReport {
    pub fn any_found(&self) -> bool {
        self.tasks
            .iter()
            .any(|task| task.report.status == JobStatus::Found)
    }

    pub fn any_failed(&self) -> bool {
        self.tasks
            .iter()
            .any(|task| task.report.status == JobStatus::Failed)
    }

    pub fn found_count(&self) -> usize {
        self.tasks
            .iter()
            .filter(|task| task.report.status == JobStatus::Found)
            .count()
    }

    pub fn failed_count(&self) -> usize {
        self.tasks
            .iter()
            .filter(|task| task.report.status == JobStatus::Failed)
            .count()
    }
}

/// Parse and validate a TOML manifest. Relative paths resolve against the
/// manifest's directory.
pub fn load_manifest(path: &Path) -> Result<BatchConfig> {
    let body = std::fs::read_to_string(path)?;
    let manifest: Manifest = toml::from_str(&body)
        .map_err(|error| AcxError::Batch(format!("manifest {}: {error}", path.display())))?;
    let absolute = std::fs::canonicalize(path)?;
    let base = absolute
        .parent()
        .ok_or_else(|| AcxError::Batch("manifest has no parent directory".to_string()))?
        .to_path_buf();

    if manifest.jobs.is_empty() {
        return Err(AcxError::Batch("manifest contains no jobs".to_string()));
    }
    if manifest.max_parallel == 0 || manifest.max_parallel > MAX_BATCH_PARALLEL {
        return Err(AcxError::Batch(format!(
            "max_parallel {} is outside 1..={MAX_BATCH_PARALLEL}",
            manifest.max_parallel
        )));
    }

    let checkpoint_root = manifest
        .checkpoint_root
        .map(|root| resolve(&base, &root))
        .unwrap_or_else(|| base.join("acx-checkpoints"));

    let mut ids = HashSet::new();
    let mut jobs = Vec::with_capacity(manifest.jobs.len());
    let mut max_threads = 0usize;
    for entry in manifest.jobs {
        validate_id(&entry.id)?;
        if !ids.insert(entry.id.clone()) {
            return Err(AcxError::Batch(format!("duplicate job id `{}`", entry.id)));
        }
        if entry.threads == 0 || entry.threads > MAX_JOB_THREADS {
            return Err(AcxError::Batch(format!(
                "job `{}` threads {} is outside 1..={MAX_JOB_THREADS}",
                entry.id, entry.threads
            )));
        }
        max_threads = max_threads.max(entry.threads);
        let attack = attack_from_entry(&entry, &base)?;
        let checkpoint = checkpoint_root.join(format!("{}.acx-checkpoint", entry.id));
        jobs.push(BatchJob {
            id: entry.id.clone(),
            spec: JobSpec {
                id: entry.id,
                archive: resolve(&base, &entry.archive),
                attack,
                threads: entry.threads,
                checkpoint,
                resume: false,
            },
            reuse_found: entry.reuse_found,
        });
    }

    let peak_threads = manifest.max_parallel.saturating_mul(max_threads);
    if peak_threads > MAX_JOB_THREADS {
        return Err(AcxError::Batch(format!(
            "max_parallel {} × max job threads {max_threads} = {peak_threads}, above the {MAX_JOB_THREADS}-thread budget",
            manifest.max_parallel
        )));
    }

    let mut warnings = Vec::new();
    let available = thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1);
    if peak_threads > available {
        warnings.push(format!(
            "batch may run {peak_threads} worker threads on {available} available CPUs; expect oversubscription"
        ));
    }

    Ok(BatchConfig {
        max_parallel: manifest.max_parallel,
        reuse_found: manifest.reuse_found,
        checkpoint_root,
        jobs,
        warnings,
    })
}

fn resolve(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

fn validate_id(id: &str) -> Result<()> {
    if id.is_empty() || id.len() > MAX_ID_BYTES {
        return Err(AcxError::Batch(format!(
            "job id {id:?} must be 1..={MAX_ID_BYTES} bytes"
        )));
    }
    if id == "." || id == ".." {
        return Err(AcxError::Batch(format!("job id {id:?} is not a file name")));
    }
    if !id
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
    {
        return Err(AcxError::Batch(format!(
            "job id {id:?} may contain only ASCII letters, digits, dot, underscore, and hyphen"
        )));
    }
    let upper = id.to_ascii_uppercase();
    let reserved = ["CON", "PRN", "AUX", "NUL"]
        .iter()
        .chain(
            [
                "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
            ]
            .iter(),
        )
        .chain(
            [
                "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
            ]
            .iter(),
        )
        .any(|name| upper == *name);
    if reserved {
        return Err(AcxError::Batch(format!(
            "job id {id:?} is a reserved Windows device name"
        )));
    }
    Ok(())
}

fn attack_from_entry(entry: &JobEntry, base: &Path) -> Result<AttackConfig> {
    let custom = [
        entry.custom_charset1.clone(),
        entry.custom_charset2.clone(),
        entry.custom_charset3.clone(),
        entry.custom_charset4.clone(),
    ];
    match entry.mode.as_str() {
        "dict" => {
            reject(entry, "masks", entry.masks.is_some(), "dict")?;
            reject(entry, "charset", entry.charset.is_some(), "dict")?;
            reject(entry, "min_len", entry.min_len.is_some(), "dict")?;
            reject(entry, "max_len", entry.max_len.is_some(), "dict")?;
            reject(entry, "rules", entry.rules.is_some(), "dict")?;
            reject(entry, "prefix_mask", entry.prefix_mask.is_some(), "dict")?;
            reject(entry, "suffix_mask", entry.suffix_mask.is_some(), "dict")?;
            reject(
                entry,
                "custom_charset*",
                custom.iter().any(Option::is_some),
                "dict",
            )?;
            let dictionary = entry
                .dictionary
                .as_ref()
                .ok_or_else(|| mode_error(entry, "dict requires `dictionary`"))?;
            Ok(AttackConfig::Dictionary {
                dictionary: resolve(base, dictionary),
            })
        }
        "mask" => {
            reject(entry, "dictionary", entry.dictionary.is_some(), "mask")?;
            reject(entry, "charset", entry.charset.is_some(), "mask")?;
            reject(entry, "min_len", entry.min_len.is_some(), "mask")?;
            reject(entry, "max_len", entry.max_len.is_some(), "mask")?;
            reject(entry, "rules", entry.rules.is_some(), "mask")?;
            reject(entry, "prefix_mask", entry.prefix_mask.is_some(), "mask")?;
            reject(entry, "suffix_mask", entry.suffix_mask.is_some(), "mask")?;
            let masks = entry
                .masks
                .as_ref()
                .filter(|masks| !masks.is_empty())
                .ok_or_else(|| mode_error(entry, "mask requires a non-empty `masks` array"))?;
            Ok(AttackConfig::Mask {
                masks: masks.clone(),
                custom,
            })
        }
        "brute" => {
            reject(entry, "dictionary", entry.dictionary.is_some(), "brute")?;
            reject(entry, "masks", entry.masks.is_some(), "brute")?;
            reject(entry, "rules", entry.rules.is_some(), "brute")?;
            reject(entry, "prefix_mask", entry.prefix_mask.is_some(), "brute")?;
            reject(entry, "suffix_mask", entry.suffix_mask.is_some(), "brute")?;
            let charset = entry
                .charset
                .as_ref()
                .ok_or_else(|| mode_error(entry, "brute requires `charset`"))?;
            let min_len = entry
                .min_len
                .ok_or_else(|| mode_error(entry, "brute requires `min_len`"))?;
            let max_len = entry
                .max_len
                .ok_or_else(|| mode_error(entry, "brute requires `max_len`"))?;
            Ok(AttackConfig::Brute {
                charset: charset.clone(),
                min_len,
                max_len,
                custom,
            })
        }
        "hybrid" => {
            reject(entry, "masks", entry.masks.is_some(), "hybrid")?;
            reject(entry, "charset", entry.charset.is_some(), "hybrid")?;
            reject(entry, "min_len", entry.min_len.is_some(), "hybrid")?;
            reject(entry, "max_len", entry.max_len.is_some(), "hybrid")?;
            let dictionary = entry
                .dictionary
                .as_ref()
                .ok_or_else(|| mode_error(entry, "hybrid requires `dictionary`"))?;
            let rules = entry.rules.clone().unwrap_or_default();
            let has_variant =
                !rules.is_empty() || entry.prefix_mask.is_some() || entry.suffix_mask.is_some();
            if !has_variant {
                return Err(mode_error(
                    entry,
                    "hybrid requires `rules`, `prefix_mask`, or `suffix_mask`",
                ));
            }
            Ok(AttackConfig::Hybrid {
                dictionary: resolve(base, dictionary),
                rules,
                prefix_mask: entry.prefix_mask.clone(),
                suffix_mask: entry.suffix_mask.clone(),
                custom,
            })
        }
        other => Err(AcxError::Batch(format!(
            "job `{}` has unsupported mode `{other}` (expected dict, mask, brute, or hybrid)",
            entry.id
        ))),
    }
}

fn reject(entry: &JobEntry, field: &str, present: bool, mode: &str) -> Result<()> {
    if present {
        Err(AcxError::Batch(format!(
            "job `{}`: `{field}` is not valid in {mode} mode",
            entry.id
        )))
    } else {
        Ok(())
    }
}

fn mode_error(entry: &JobEntry, message: &str) -> AcxError {
    AcxError::Batch(format!("job `{}`: {message}", entry.id))
}

/// Validate every job (archive preflight + attack parameters) before any task
/// starts.
pub fn validate_batch(config: &BatchConfig) -> Result<()> {
    for job in &config.jobs {
        validate_job(&job.spec)
            .map_err(|error| AcxError::Batch(format!("job `{}`: {error}", job.id)))?;
    }
    Ok(())
}

/// Dry-run estimates for every job, in manifest order.
pub fn estimate_batch(config: &BatchConfig) -> Vec<BatchPreview> {
    config
        .jobs
        .iter()
        .map(|job| BatchPreview {
            id: job.id.clone(),
            result: estimate_job(&job.spec),
        })
        .collect()
}

/// Stop signal shared by all running batch tasks.
pub struct BatchControl {
    stopped: AtomicBool,
    controls: Mutex<Vec<Arc<RunControl>>>,
}

impl Default for BatchControl {
    fn default() -> Self {
        Self::new()
    }
}

impl BatchControl {
    pub fn new() -> Self {
        Self {
            stopped: AtomicBool::new(false),
            controls: Mutex::new(Vec::new()),
        }
    }

    pub fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        if let Ok(controls) = self.controls.lock() {
            for control in controls.iter() {
                control.stop();
            }
        }
    }

    pub fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::SeqCst)
    }

    fn register(&self, control: &Arc<RunControl>) {
        if self.is_stopped() {
            control.stop();
        }
        if let Ok(mut controls) = self.controls.lock() {
            controls.push(Arc::clone(control));
        }
    }
}

pub struct BatchOptions {
    pub max_parallel: Option<usize>,
    pub reuse_found: Option<bool>,
    pub fail_fast: bool,
    pub control: Arc<BatchControl>,
}

/// Run every job, at most `max_parallel` at a time, preserving manifest order
/// in the report.
pub fn run_batch(config: &BatchConfig, options: &BatchOptions) -> Result<BatchReport> {
    validate_batch(config)?;
    std::fs::create_dir_all(&config.checkpoint_root)?;
    let max_parallel = options
        .max_parallel
        .unwrap_or(config.max_parallel)
        .clamp(1, config.jobs.len().max(1));
    if max_parallel > MAX_BATCH_PARALLEL {
        return Err(AcxError::Batch(format!(
            "max_parallel {max_parallel} exceeds {MAX_BATCH_PARALLEL}"
        )));
    }
    let max_threads = config
        .jobs
        .iter()
        .map(|job| job.spec.threads)
        .max()
        .unwrap_or(1);
    let peak_threads = max_parallel.saturating_mul(max_threads);
    if peak_threads > MAX_JOB_THREADS {
        return Err(AcxError::Batch(format!(
            "max_parallel {max_parallel} × max job threads {max_threads} = {peak_threads}, above the {MAX_JOB_THREADS}-thread budget"
        )));
    }
    let reuse_found = options.reuse_found.unwrap_or(config.reuse_found);
    let jobs = Arc::new(config.jobs.clone());
    let next = Arc::new(AtomicUsize::new(0));
    let fail_fast = Arc::new(AtomicBool::new(false));
    let cache = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let results: Arc<Mutex<Vec<Option<JobReport>>>> =
        Arc::new(Mutex::new((0..jobs.len()).map(|_| None).collect()));

    thread::scope(|scope| {
        for _ in 0..max_parallel {
            let jobs = Arc::clone(&jobs);
            let next = Arc::clone(&next);
            let fail_fast = Arc::clone(&fail_fast);
            let cache = Arc::clone(&cache);
            let results = Arc::clone(&results);
            let control = Arc::clone(&options.control);
            scope.spawn(move || loop {
                if control.is_stopped() || (options.fail_fast && fail_fast.load(Ordering::SeqCst)) {
                    break;
                }
                let index = next.fetch_add(1, Ordering::SeqCst);
                if index >= jobs.len() {
                    break;
                }
                let job = &jobs[index];
                let reuse = job.reuse_found.unwrap_or(reuse_found);
                let prepass = if reuse {
                    cache.lock().map(|cache| cache.clone()).unwrap_or_default()
                } else {
                    Vec::new()
                };
                let mut spec = job.spec.clone();
                spec.resume = spec.checkpoint.exists();
                let checkpoint = spec.checkpoint.clone();
                let task_control = Arc::new(RunControl::new());
                control.register(&task_control);
                if control.is_stopped() {
                    task_control.stop();
                }
                let report = match run_job(&spec, task_control, &prepass, &mut SilentObserver) {
                    Ok(report) => report,
                    Err(error) => JobReport::failed(checkpoint, error, Duration::ZERO),
                };
                if report.status == JobStatus::Found && reuse {
                    if let Some(password) = report.password.as_ref() {
                        if let Ok(mut cache) = cache.lock() {
                            if !cache.iter().any(|cached| cached == password) {
                                cache.push(password.clone());
                            }
                        }
                    }
                }
                if report.status == JobStatus::Failed && options.fail_fast {
                    fail_fast.store(true, Ordering::SeqCst);
                }
                if let Ok(mut results) = results.lock() {
                    results[index] = Some(report);
                }
            });
        }
    });

    let results = results
        .lock()
        .map(|mut results| results.iter_mut().map(Option::take).collect::<Vec<_>>())
        .unwrap_or_else(|_| Vec::new());
    let mut tasks = Vec::with_capacity(jobs.len());
    for (job, report) in jobs.iter().zip(results) {
        tasks.push(BatchTaskReport {
            id: job.id.clone(),
            report: report.unwrap_or_else(|| JobReport::cancelled(job.spec.checkpoint.clone())),
        });
    }
    Ok(BatchReport {
        tasks,
        stopped: options.control.is_stopped(),
        fail_fast_triggered: fail_fast.load(Ordering::SeqCst),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_ID: AtomicU64 = AtomicU64::new(0);

    fn scratch_dir() -> PathBuf {
        let mut path = std::env::current_exe().unwrap_or_default();
        if path.pop() {
            path.pop();
        }
        path.push("acx-test-tmp");
        std::fs::create_dir_all(&path).expect("create scratch dir");
        path
    }

    struct TempManifest {
        dir: PathBuf,
        path: PathBuf,
    }

    impl TempManifest {
        fn new(body: &str) -> Self {
            let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            let dir = scratch_dir().join(format!("acx-batch-{}-{id}", std::process::id()));
            std::fs::create_dir_all(&dir).expect("create manifest dir");
            let path = dir.join("jobs.toml");
            std::fs::write(&path, body).expect("write manifest");
            Self { dir, path }
        }
    }

    impl Drop for TempManifest {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn manifest(body: &str) -> BatchConfig {
        load_manifest(&TempManifest::new(body).path).expect("load manifest")
    }

    #[test]
    fn loads_all_four_modes_and_resolves_relative_paths() {
        let config = manifest(
            r#"
max_parallel = 2
checkpoint_root = "runs"

[[jobs]]
id = "dict-job"
archive = "a.zip"
mode = "dict"
dictionary = "d.txt"

[[jobs]]
id = "mask-job"
archive = "b.zip"
mode = "mask"
masks = ["?d?d"]

[[jobs]]
id = "brute-job"
archive = "c.7z"
mode = "brute"
charset = "?l"
min_len = 1
max_len = 2

[[jobs]]
id = "hybrid-job"
archive = "d.rar"
mode = "hybrid"
dictionary = "d.txt"
rules = ["identity"]
suffix_mask = "?d"
"#,
        );
        assert_eq!(config.max_parallel, 2);
        assert_eq!(config.jobs.len(), 4);
        assert!(config.jobs[0].spec.archive.ends_with("a.zip"));
        assert!(config.jobs[0].spec.archive.is_absolute());
        assert_eq!(
            config.jobs[1].spec.checkpoint,
            config.checkpoint_root.join("mask-job.acx-checkpoint")
        );
        assert!(config.warnings.is_empty() || config.warnings[0].contains("oversubscription"));
    }

    #[test]
    fn rejects_unknown_fields_and_duplicate_ids() {
        let temp = TempManifest::new(
            r#"
[[jobs]]
id = "a"
archive = "a.zip"
mode = "dict"
dictionary = "d.txt"
unexpected = true
"#,
        );
        let error = load_manifest(&temp.path).expect_err("unknown field");
        assert!(matches!(error, AcxError::Batch(_)), "{error}");

        let temp = TempManifest::new(
            r#"
[[jobs]]
id = "a"
archive = "a.zip"
mode = "dict"
dictionary = "d.txt"

[[jobs]]
id = "a"
archive = "b.zip"
mode = "dict"
dictionary = "d.txt"
"#,
        );
        let error = load_manifest(&temp.path).expect_err("duplicate id");
        assert!(error.to_string().contains("duplicate job id"), "{error}");
    }

    #[test]
    fn rejects_invalid_ids_and_mode_fields() {
        for id in ["../x", "a/b", "a:b", "", "CON", ".."] {
            let body = format!(
                "[[jobs]]\nid = \"{id}\"\narchive = \"a.zip\"\nmode = \"dict\"\ndictionary = \"d.txt\"\n"
            );
            let temp = TempManifest::new(&body);
            assert!(
                load_manifest(&temp.path).is_err(),
                "id {id:?} must be rejected"
            );
        }

        let temp = TempManifest::new(
            "[[jobs]]\nid = \"a\"\narchive = \"a.zip\"\nmode = \"mask\"\nmasks = [\"?d\"]\ndictionary = \"d.txt\"\n",
        );
        let error = load_manifest(&temp.path).expect_err("mask + dictionary");
        assert!(
            error.to_string().contains("not valid in mask mode"),
            "{error}"
        );
    }

    #[test]
    fn rejects_parallel_thread_budget_and_empty_manifest() {
        let temp = TempManifest::new("max_parallel = 2\njobs = []\n");
        assert!(load_manifest(&temp.path).is_err());

        let temp = TempManifest::new(
            r#"
max_parallel = 4

[[jobs]]
id = "a"
archive = "a.zip"
mode = "brute"
charset = "?l"
min_len = 1
max_len = 2
threads = 100

[[jobs]]
id = "b"
archive = "b.zip"
mode = "brute"
charset = "?l"
min_len = 1
max_len = 2
threads = 100
"#,
        );
        let error = load_manifest(&temp.path).expect_err("thread budget");
        assert!(error.to_string().contains("thread budget"), "{error}");
    }

    #[test]
    fn batch_control_stops_registered_and_late_tasks() {
        let control = BatchControl::new();
        let running = Arc::new(RunControl::new());
        control.register(&running);
        assert!(!running.is_stopping());
        control.stop();
        assert!(control.is_stopped());
        assert!(running.is_stopping());

        let late = Arc::new(RunControl::new());
        control.register(&late);
        assert!(late.is_stopping());
    }

    #[test]
    fn mode_defaults_and_per_job_reuse_override() {
        let config = manifest(
            r#"
reuse_found = true

[[jobs]]
id = "a"
archive = "a.zip"
mode = "brute"
charset = "?l"
min_len = 1
max_len = 1
reuse_found = false
"#,
        );
        assert!(config.reuse_found);
        assert_eq!(config.jobs[0].reuse_found, Some(false));
        assert_eq!(config.jobs[0].spec.threads, 1);
    }
}
