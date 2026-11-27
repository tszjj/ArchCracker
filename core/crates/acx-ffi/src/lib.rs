// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

//! ArchCracker C ABI v1.
//!
//! The ABI is a thin boundary: it copies borrowed C inputs into Rust-owned
//! values, converts errors to stable status codes, and runs one job at a time
//! per handle on a background thread. Business logic stays in `acx-core`.

use acx_core::archive::ArchiveInfo;
use acx_core::encoding::EncodingSelection;
use acx_core::error::AcxError;
use acx_core::job::{self, AttackConfig, JobObserver, JobPreview, JobSpec, ProgressHook};
use acx_core::scheduler::{RunControl, RunProgress};
use std::cell::RefCell;
use std::ffi::{c_char, c_void, CStr, CString};
use std::mem::size_of;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock};
use std::thread::{self, JoinHandle};

/// Numeric status codes shared with `include/acx.h`.
pub const ACX_OK: i32 = 0;
pub const ACX_ERR_INVALID_ARG: i32 = 1;
pub const ACX_ERR_IO: i32 = 2;
pub const ACX_ERR_UNSUPPORTED: i32 = 3;
pub const ACX_ERR_ARCHIVE: i32 = 4;
pub const ACX_ERR_MISSING_VOLUME: i32 = 5;
pub const ACX_ERR_CANCELLED: i32 = 6;
pub const ACX_ERR_INTERNAL: i32 = 7;
pub const ACX_ERR_PANIC: i32 = 8;
pub const ACX_ERR_UNKNOWN: i32 = 9;

const ACX_ABI_V1: u32 = 1;
const ACX_INPUT_PATH: u32 = 0;
const ACX_INPUT_FD: u32 = 1;
const ACX_INPUT_URI: u32 = 2;
const ACX_ATTACK_DICT: u32 = 0;
const ACX_ATTACK_MASK: u32 = 1;
const ACX_ATTACK_BRUTE: u32 = 2;
const ACX_ATTACK_HYBRID: u32 = 3;

pub const ACX_RUN_IDLE: u32 = 0;
pub const ACX_RUN_RUNNING: u32 = 1;
pub const ACX_RUN_PAUSED: u32 = 2;
pub const ACX_RUN_STOPPED: u32 = 3;
pub const ACX_RUN_FINISHED: u32 = 4;
pub const ACX_RUN_FAILED: u32 = 5;

thread_local! {
    static LAST_ERROR: RefCell<CString> = RefCell::new(CString::default());
}

static PRODUCT_C: OnceLock<CString> = OnceLock::new();
static VERSION_C: OnceLock<CString> = OnceLock::new();

fn product_c() -> &'static CString {
    PRODUCT_C.get_or_init(|| CString::new(acx_core::PRODUCT).unwrap_or_default())
}

fn version_c() -> &'static CString {
    VERSION_C.get_or_init(|| CString::new(acx_core::VERSION).unwrap_or_default())
}

fn cstring_or_empty(message: &str) -> CString {
    CString::new(message.replace('\0', " ")).unwrap_or_default()
}

fn set_last_error(message: &str) {
    let value = cstring_or_empty(message);
    LAST_ERROR.with(|slot| {
        *slot.borrow_mut() = value;
    });
}

fn set_handle_error(inner: &Mutex<HandleInner>, message: &str) {
    lock_inner(inner).last_error = cstring_or_empty(message);
}

fn status_for_error(error: &AcxError) -> i32 {
    match error {
        AcxError::Io(_) => ACX_ERR_IO,
        AcxError::MissingVolume(_) => ACX_ERR_MISSING_VOLUME,
        AcxError::Cancelled => ACX_ERR_CANCELLED,
        AcxError::Unsupported(_) => ACX_ERR_UNSUPPORTED,
        AcxError::NotEncrypted
        | AcxError::EmptyArchive
        | AcxError::Truncated(_)
        | AcxError::Corrupt(_)
        | AcxError::Zip(_)
        | AcxError::SevenZ(_)
        | AcxError::External(_) => ACX_ERR_ARCHIVE,
        AcxError::Attack(_) | AcxError::Dictionary(_) | AcxError::Batch(_) => ACX_ERR_INVALID_ARG,
        AcxError::Checkpoint(_) | AcxError::Internal(_) => ACX_ERR_INTERNAL,
    }
}

fn finish(result: std::result::Result<(), AcxError>) -> i32 {
    match result {
        Ok(()) => ACX_OK,
        Err(error) => {
            set_last_error(&error.to_string());
            status_for_error(&error)
        }
    }
}

fn finish_handle(handle: *mut AcxHandle, result: std::result::Result<(), AcxError>) -> i32 {
    if let Err(error) = &result {
        if !handle.is_null() {
            // SAFETY: handle was validated in the implementation before this point.
            let handle_ref = unsafe { &*handle };
            set_handle_error(&handle_ref.inner, &error.to_string());
        }
    }
    finish(result)
}

/// Stable ABI revision.
#[no_mangle]
pub extern "C" fn acx_abi_version() -> u32 {
    ACX_ABI_V1
}

/// Product name, e.g. `ArchCracker`.
#[no_mangle]
pub extern "C" fn acx_product() -> *const c_char {
    product_c().as_ptr()
}

/// Core version, e.g. `0.0.1`.
#[no_mangle]
pub extern "C" fn acx_version() -> *const c_char {
    version_c().as_ptr()
}

/// Stable name for a status code. Unknown codes return `ACX_ERR_UNKNOWN`.
#[no_mangle]
pub extern "C" fn acx_status_name(status: i32) -> *const c_char {
    let name: &[u8] = match status {
        ACX_OK => b"ACX_OK\0",
        ACX_ERR_INVALID_ARG => b"ACX_ERR_INVALID_ARG\0",
        ACX_ERR_IO => b"ACX_ERR_IO\0",
        ACX_ERR_UNSUPPORTED => b"ACX_ERR_UNSUPPORTED\0",
        ACX_ERR_ARCHIVE => b"ACX_ERR_ARCHIVE\0",
        ACX_ERR_MISSING_VOLUME => b"ACX_ERR_MISSING_VOLUME\0",
        ACX_ERR_CANCELLED => b"ACX_ERR_CANCELLED\0",
        ACX_ERR_INTERNAL => b"ACX_ERR_INTERNAL\0",
        ACX_ERR_PANIC => b"ACX_ERR_PANIC\0",
        ACX_ERR_UNKNOWN => b"ACX_ERR_UNKNOWN\0",
        _ => b"ACX_ERR_UNKNOWN\0",
    };
    name.as_ptr().cast()
}

#[repr(C)]
pub struct AcxConfig {
    pub struct_size: u32,
    pub version: u32,
    pub reserved: [u64; 4],
}

#[repr(C)]
pub struct AcxInput {
    pub struct_size: u32,
    pub version: u32,
    pub kind: u32,
    pub path: *const c_char,
    pub fd: isize,
    pub uri: *const c_char,
    pub reserved: [u64; 4],
}

#[repr(C)]
pub struct AcxAttackSpec {
    pub struct_size: u32,
    pub version: u32,
    pub input: AcxInput,
    pub mode: u32,
    pub dictionary_path: *const c_char,
    pub masks: *const *const c_char,
    pub mask_count: u32,
    pub charset: *const c_char,
    pub min_len: u32,
    pub max_len: u32,
    pub custom: [*const c_char; 4],
    pub rules: *const *const c_char,
    pub rule_count: u32,
    pub prefix_mask: *const c_char,
    pub suffix_mask: *const c_char,
    pub threads: u32,
    pub checkpoint_path: *const c_char,
    pub resume: u8,
    pub encoding: *const c_char,
    pub strict: u8,
    pub rar_no_fast_reject: u8,
    pub report_stats: u8,
    pub reserved: [u64; 8],
}

type ProgressFn = Option<unsafe extern "C" fn(*mut c_void, u64, u64, f64, u64)>;
type HitFn = Option<unsafe extern "C" fn(*mut c_void, *const u8, usize)>;
type LogFn = Option<unsafe extern "C" fn(*mut c_void, i32, *const c_char)>;
type FinishedFn = Option<unsafe extern "C" fn(*mut c_void, i32)>;

#[repr(C)]
pub struct AcxCallbacks {
    pub struct_size: u32,
    pub version: u32,
    pub on_progress: ProgressFn,
    pub on_hit: HitFn,
    pub on_log: LogFn,
    pub on_finished: FinishedFn,
    pub user: *mut c_void,
    pub reserved: [u64; 4],
}

#[repr(C)]
pub struct AcxStatusInfo {
    pub struct_size: u32,
    pub version: u32,
    pub state: u32,
    pub tried: u64,
    pub total: u64,
    pub rate: f64,
    pub eta_sec: u64,
    pub last_status: i32,
    pub reserved: [u64; 4],
}

#[derive(Clone, Copy, Default)]
struct CallbackSet {
    on_progress: ProgressFn,
    on_hit: HitFn,
    on_log: LogFn,
    on_finished: FinishedFn,
    /// User pointer is opaque to Rust; the caller keeps it valid until destroy.
    user: usize,
}

// SAFETY: callback pointers and the opaque user value are documented as valid
// for the handle lifetime and safe to touch from native worker threads.
unsafe impl Send for CallbackSet {}
unsafe impl Sync for CallbackSet {}

#[derive(Default)]
struct GateState {
    closed: bool,
    active: usize,
}

/// Ensures no callback starts after `close` returns.
struct CallbackGate {
    state: Mutex<GateState>,
    idle: Condvar,
}

impl CallbackGate {
    fn new() -> Self {
        Self {
            state: Mutex::new(GateState::default()),
            idle: Condvar::new(),
        }
    }

    fn reopen(&self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.closed = false;
    }

    fn invoke(&self, callbacks: &CallbackSet, action: impl FnOnce(&CallbackSet)) {
        {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if state.closed {
                return;
            }
            state.active += 1;
        }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| action(callbacks)));
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.active -= 1;
        if state.active == 0 {
            self.idle.notify_all();
        }
        if result.is_err() {
            set_last_error("native callback panicked");
        }
    }

    fn close(&self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.closed = true;
        while state.active > 0 {
            state = self.idle.wait(state).unwrap_or_else(|e| e.into_inner());
        }
    }
}

#[derive(Clone, Copy, Default)]
struct ProgressSnapshot {
    tried: u64,
    total: u64,
    rate: f64,
    eta_sec: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum HandleState {
    Idle,
    Running,
    Paused,
    Stopped,
    Finished,
    Failed,
}

impl HandleState {
    fn as_abi(self) -> u32 {
        match self {
            Self::Idle => ACX_RUN_IDLE,
            Self::Running => ACX_RUN_RUNNING,
            Self::Paused => ACX_RUN_PAUSED,
            Self::Stopped => ACX_RUN_STOPPED,
            Self::Finished => ACX_RUN_FINISHED,
            Self::Failed => ACX_RUN_FAILED,
        }
    }
}

struct HandleInner {
    state: HandleState,
    control: Option<Arc<RunControl>>,
    worker: Option<JoinHandle<()>>,
    progress: ProgressSnapshot,
    last_status: i32,
    last_error: CString,
    callbacks: Arc<CallbackSet>,
}

/// Opaque native handle. One handle owns at most one running job.
pub struct AcxHandle {
    inner: Arc<Mutex<HandleInner>>,
    gate: Arc<CallbackGate>,
}

fn lock_inner(inner: &Mutex<HandleInner>) -> MutexGuard<'_, HandleInner> {
    inner.lock().unwrap_or_else(|e| e.into_inner())
}

fn update_progress(inner: &Mutex<HandleInner>, progress: ProgressSnapshot) {
    lock_inner(inner).progress = progress;
}

fn finish_state(
    inner: &Mutex<HandleInner>,
    state: HandleState,
    status: i32,
    progress: ProgressSnapshot,
) {
    let mut guard = lock_inner(inner);
    guard.state = state;
    guard.last_status = status;
    guard.progress = progress;
}

fn validate_layout(
    struct_size: u32,
    version: u32,
    expected: usize,
) -> std::result::Result<(), AcxError> {
    if version != ACX_ABI_V1 {
        return Err(AcxError::Attack(format!(
            "unsupported ABI version {version}; expected {ACX_ABI_V1}"
        )));
    }
    if (struct_size as usize) < expected {
        return Err(AcxError::Attack(format!(
            "struct_size {struct_size} is smaller than ABI v1 size {expected}"
        )));
    }
    Ok(())
}

unsafe fn read_cstr(ptr: *const c_char, field: &str) -> std::result::Result<String, AcxError> {
    if ptr.is_null() {
        return Err(AcxError::Attack(format!("{field} is null")));
    }
    // SAFETY: caller supplies a NUL-terminated C string that stays valid for the call.
    let value = CStr::from_ptr(ptr)
        .to_str()
        .map_err(|error| AcxError::Attack(format!("{field} is not valid UTF-8: {error}")))?;
    Ok(value.to_owned())
}

unsafe fn optional_cstr(ptr: *const c_char) -> std::result::Result<Option<String>, AcxError> {
    if ptr.is_null() {
        return Ok(None);
    }
    // SAFETY: caller supplies a NUL-terminated C string that stays valid for the call.
    Ok(Some(
        CStr::from_ptr(ptr)
            .to_str()
            .map_err(|error| AcxError::Attack(format!("string is not valid UTF-8: {error}")))?
            .to_owned(),
    ))
}

unsafe fn string_array(
    ptr: *const *const c_char,
    count: u32,
    field: &str,
) -> std::result::Result<Vec<String>, AcxError> {
    if count == 0 {
        return Ok(Vec::new());
    }
    if ptr.is_null() {
        return Err(AcxError::Attack(format!("{field} is null")));
    }
    let mut output = Vec::with_capacity(count as usize);
    // SAFETY: caller supplies an array of at least `count` C string pointers.
    let entries = std::slice::from_raw_parts(ptr, count as usize);
    for entry in entries {
        output.push(read_cstr(*entry, field)?);
    }
    Ok(output)
}

fn flag(value: u8, field: &str) -> std::result::Result<bool, AcxError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(AcxError::Attack(format!("{field} must be 0 or 1"))),
    }
}

unsafe fn callbacks_from(
    callbacks: *const AcxCallbacks,
) -> std::result::Result<Arc<CallbackSet>, AcxError> {
    if callbacks.is_null() {
        return Ok(Arc::new(CallbackSet::default()));
    }
    // SAFETY: caller supplies a valid callbacks struct for the duration of the call.
    let native = &*callbacks;
    validate_layout(
        native.struct_size,
        native.version,
        size_of::<AcxCallbacks>(),
    )?;
    Ok(Arc::new(CallbackSet {
        on_progress: native.on_progress,
        on_hit: native.on_hit,
        on_log: native.on_log,
        on_finished: native.on_finished,
        user: native.user as usize,
    }))
}

unsafe fn build_job_spec(native: &AcxAttackSpec) -> std::result::Result<JobSpec, AcxError> {
    validate_layout(
        native.struct_size,
        native.version,
        size_of::<AcxAttackSpec>(),
    )?;
    validate_layout(
        native.input.struct_size,
        native.input.version,
        size_of::<AcxInput>(),
    )?;

    let archive = match native.input.kind {
        ACX_INPUT_PATH => PathBuf::from(read_cstr(native.input.path, "input.path")?),
        ACX_INPUT_FD => {
            return Err(AcxError::Unsupported(
                "ACX_INPUT_FD is reserved for JNI and not available in the desktop ABI".to_string(),
            ))
        }
        ACX_INPUT_URI => {
            return Err(AcxError::Unsupported(
                "ACX_INPUT_URI is reserved for NAPI and not available in the desktop ABI"
                    .to_string(),
            ))
        }
        other => return Err(AcxError::Attack(format!("unknown AcxInput kind {other}"))),
    };

    let mut custom: [Option<String>; 4] = Default::default();
    for (index, slot) in native.custom.iter().enumerate() {
        custom[index] = optional_cstr(*slot)?;
    }

    let attack = match native.mode {
        ACX_ATTACK_DICT => AttackConfig::Dictionary {
            dictionary: PathBuf::from(read_cstr(native.dictionary_path, "dictionary_path")?),
        },
        ACX_ATTACK_MASK => AttackConfig::Mask {
            masks: string_array(native.masks, native.mask_count, "masks")?,
            custom,
        },
        ACX_ATTACK_BRUTE => AttackConfig::Brute {
            charset: read_cstr(native.charset, "charset")?,
            min_len: native.min_len as usize,
            max_len: native.max_len as usize,
            custom,
        },
        ACX_ATTACK_HYBRID => AttackConfig::Hybrid {
            dictionary: PathBuf::from(read_cstr(native.dictionary_path, "dictionary_path")?),
            rules: string_array(native.rules, native.rule_count, "rules")?,
            prefix_mask: optional_cstr(native.prefix_mask)?,
            suffix_mask: optional_cstr(native.suffix_mask)?,
            custom,
        },
        other => return Err(AcxError::Attack(format!("unknown attack mode {other}"))),
    };

    let encoding = match optional_cstr(native.encoding)? {
        None => EncodingSelection::Auto,
        Some(spec) => EncodingSelection::parse(&spec)?,
    };
    let checkpoint = match optional_cstr(native.checkpoint_path)? {
        Some(path) => PathBuf::from(path),
        None => default_checkpoint(&archive),
    };
    let threads = if native.threads == 0 {
        thread::available_parallelism().map_or(1, |value| value.get())
    } else {
        native.threads as usize
    };

    Ok(JobSpec {
        id: "ffi".to_string(),
        archive,
        attack,
        threads,
        checkpoint,
        resume: flag(native.resume, "resume")?,
        encoding,
        strict: flag(native.strict, "strict")?,
        rar_no_fast_reject: flag(native.rar_no_fast_reject, "rar_no_fast_reject")?,
        report_stats: flag(native.report_stats, "report_stats")?,
    })
}

fn default_checkpoint(archive: &Path) -> PathBuf {
    PathBuf::from(format!("{}.acx-checkpoint", archive.display()))
}

fn log_message(callbacks: &CallbackSet, gate: &CallbackGate, level: i32, message: &str) {
    let value = cstring_or_empty(message);
    gate.invoke(callbacks, |set| {
        if let Some(callback) = set.on_log {
            // SAFETY: user data remains valid for the handle lifetime.
            unsafe { callback(set.user as *mut c_void, level, value.as_ptr()) };
        }
    });
}

struct FfiObserver {
    callbacks: Arc<CallbackSet>,
    gate: Arc<CallbackGate>,
}

impl JobObserver for FfiObserver {
    fn archive(&mut self, _info: &ArchiveInfo) {
        log_message(&self.callbacks, &self.gate, 1, "archive preflight complete");
    }

    fn prepared(&mut self, preview: &JobPreview) {
        log_message(
            &self.callbacks,
            &self.gate,
            1,
            &format!("job prepared: {} candidates", preview.estimate.total),
        );
    }
}

fn progress_values(progress: &RunProgress) -> (f64, u64) {
    let seconds = progress.elapsed.as_secs_f64();
    let rate = if seconds > 0.0 {
        progress.tried as f64 / seconds
    } else {
        0.0
    };
    let remaining = progress.total.saturating_sub(progress.tried);
    let eta = if rate > 0.0 && remaining > 0 {
        ((remaining as f64 / rate).ceil()).min(u64::MAX as f64) as u64
    } else {
        0
    };
    (rate, eta)
}

fn create_impl(
    config: *const AcxConfig,
    out: *mut *mut AcxHandle,
) -> std::result::Result<(), AcxError> {
    if out.is_null() {
        return Err(AcxError::Attack("out handle pointer is null".to_string()));
    }
    // SAFETY: caller supplies an out pointer that can store one handle pointer.
    unsafe { *out = std::ptr::null_mut() };
    if !config.is_null() {
        // SAFETY: caller supplies a valid config struct for the duration of the call.
        let native = unsafe { &*config };
        validate_layout(native.struct_size, native.version, size_of::<AcxConfig>())?;
    }
    let handle = Box::new(AcxHandle {
        inner: Arc::new(Mutex::new(HandleInner {
            state: HandleState::Idle,
            control: None,
            worker: None,
            progress: ProgressSnapshot::default(),
            last_status: ACX_OK,
            last_error: CString::default(),
            callbacks: Arc::new(CallbackSet::default()),
        })),
        gate: Arc::new(CallbackGate::new()),
    });
    // SAFETY: out was validated above and now receives an owned boxed handle.
    unsafe { *out = Box::into_raw(handle) };
    Ok(())
}

fn start_impl(
    handle: *mut AcxHandle,
    spec: *const AcxAttackSpec,
    callbacks: *const AcxCallbacks,
) -> std::result::Result<(), AcxError> {
    if handle.is_null() {
        return Err(AcxError::Attack("handle is null".to_string()));
    }
    if spec.is_null() {
        return Err(AcxError::Attack("attack spec is null".to_string()));
    }
    // SAFETY: caller supplies a valid attack spec for the duration of the call.
    let job_spec = unsafe { build_job_spec(&*spec)? };
    job::validate_job(&job_spec)?;
    let callbacks = unsafe { callbacks_from(callbacks)? };

    // SAFETY: handle was validated above and points to a live AcxHandle.
    let handle_ref = unsafe { &*handle };
    {
        let mut inner = lock_inner(&handle_ref.inner);
        if inner.worker.is_some() {
            return Err(AcxError::Attack(
                "a job is already running on this handle".to_string(),
            ));
        }
        inner.state = HandleState::Running;
        inner.progress = ProgressSnapshot::default();
        inner.last_status = ACX_OK;
        inner.callbacks = Arc::clone(&callbacks);
    }
    handle_ref.gate.reopen();

    let control = Arc::new(RunControl::new());
    {
        let mut inner = lock_inner(&handle_ref.inner);
        inner.control = Some(Arc::clone(&control));
    }

    let state = Arc::clone(&handle_ref.inner);
    let gate = Arc::clone(&handle_ref.gate);
    let worker_callbacks = Arc::clone(&callbacks);
    let worker_gate = Arc::clone(&gate);
    let worker_control = Arc::clone(&control);
    let worker_spec = job_spec;

    let hook_state = Arc::clone(&state);
    let hook_callbacks = Arc::clone(&callbacks);
    let hook_gate = Arc::clone(&gate);
    let hook: ProgressHook = Arc::new(move |progress: RunProgress| {
        let (rate, eta_sec) = progress_values(&progress);
        update_progress(
            &hook_state,
            ProgressSnapshot {
                tried: progress.tried,
                total: progress.total,
                rate,
                eta_sec,
            },
        );
        hook_gate.invoke(&hook_callbacks, |set| {
            if let Some(callback) = set.on_progress {
                // SAFETY: user data remains valid for the handle lifetime.
                unsafe {
                    callback(
                        set.user as *mut c_void,
                        progress.tried,
                        progress.total,
                        rate,
                        eta_sec,
                    )
                };
            }
        });
    });

    let worker = thread::spawn(move || {
        let mut observer = FfiObserver {
            callbacks: worker_callbacks.clone(),
            gate: worker_gate.clone(),
        };
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            job::run_job_with_progress(&worker_spec, worker_control, &[], &mut observer, Some(hook))
        }));
        match outcome {
            Ok(Ok(report)) => {
                let status = match report.status {
                    job::JobStatus::Found | job::JobStatus::NotFound => ACX_OK,
                    job::JobStatus::Stopped | job::JobStatus::Cancelled => ACX_OK,
                    job::JobStatus::Failed => report
                        .error
                        .as_ref()
                        .map(status_for_error)
                        .unwrap_or(ACX_ERR_INTERNAL),
                };
                let final_state = match report.status {
                    job::JobStatus::Found | job::JobStatus::NotFound => HandleState::Finished,
                    job::JobStatus::Stopped | job::JobStatus::Cancelled => HandleState::Stopped,
                    job::JobStatus::Failed => HandleState::Failed,
                };
                if status != ACX_OK {
                    let message = report
                        .error
                        .as_ref()
                        .map(ToString::to_string)
                        .unwrap_or_else(|| "job failed".to_string());
                    set_handle_error(&state, &message);
                }
                finish_state(
                    &state,
                    final_state,
                    status,
                    ProgressSnapshot {
                        tried: report.tried,
                        total: report.total,
                        rate: 0.0,
                        eta_sec: 0,
                    },
                );
                if let Some(password) = report.password {
                    worker_gate.invoke(&worker_callbacks, |set| {
                        if let Some(callback) = set.on_hit {
                            // SAFETY: password bytes are valid for this call only.
                            unsafe {
                                callback(set.user as *mut c_void, password.as_ptr(), password.len())
                            };
                        }
                    });
                }
                log_message(
                    &worker_callbacks,
                    &worker_gate,
                    1,
                    &format!("job finished: {:?}", report.status),
                );
                worker_gate.invoke(&worker_callbacks, |set| {
                    if let Some(callback) = set.on_finished {
                        // SAFETY: user data remains valid for the handle lifetime.
                        unsafe { callback(set.user as *mut c_void, status) };
                    }
                });
            }
            Ok(Err(error)) => {
                let status = status_for_error(&error);
                set_handle_error(&state, &error.to_string());
                finish_state(
                    &state,
                    HandleState::Failed,
                    status,
                    ProgressSnapshot::default(),
                );
                log_message(&worker_callbacks, &worker_gate, 2, &error.to_string());
                worker_gate.invoke(&worker_callbacks, |set| {
                    if let Some(callback) = set.on_finished {
                        // SAFETY: user data remains valid for the handle lifetime.
                        unsafe { callback(set.user as *mut c_void, status) };
                    }
                });
            }
            Err(_) => {
                set_handle_error(&state, "Rust panic caught in job");
                finish_state(
                    &state,
                    HandleState::Failed,
                    ACX_ERR_PANIC,
                    ProgressSnapshot::default(),
                );
                log_message(
                    &worker_callbacks,
                    &worker_gate,
                    2,
                    "Rust panic caught in job",
                );
                worker_gate.invoke(&worker_callbacks, |set| {
                    if let Some(callback) = set.on_finished {
                        // SAFETY: user data remains valid for the handle lifetime.
                        unsafe { callback(set.user as *mut c_void, ACX_ERR_PANIC) };
                    }
                });
            }
        }
    });

    {
        let mut inner = lock_inner(&handle_ref.inner);
        inner.worker = Some(worker);
    }
    Ok(())
}

fn pause_impl(handle: *mut AcxHandle) -> std::result::Result<(), AcxError> {
    if handle.is_null() {
        return Err(AcxError::Attack("handle is null".to_string()));
    }
    // SAFETY: handle was validated above.
    let handle_ref = unsafe { &*handle };
    let control = {
        let inner = lock_inner(&handle_ref.inner);
        inner.control.clone()
    };
    let control = control.ok_or_else(|| AcxError::Attack("no job has been started".to_string()))?;
    if !control.pause() {
        return Err(AcxError::Attack("job is not running".to_string()));
    }
    lock_inner(&handle_ref.inner).state = HandleState::Paused;
    Ok(())
}

fn resume_impl(handle: *mut AcxHandle) -> std::result::Result<(), AcxError> {
    if handle.is_null() {
        return Err(AcxError::Attack("handle is null".to_string()));
    }
    // SAFETY: handle was validated above.
    let handle_ref = unsafe { &*handle };
    let control = {
        let inner = lock_inner(&handle_ref.inner);
        inner.control.clone()
    };
    let control = control.ok_or_else(|| AcxError::Attack("no job has been started".to_string()))?;
    if !control.resume() {
        return Err(AcxError::Attack("job is not paused".to_string()));
    }
    lock_inner(&handle_ref.inner).state = HandleState::Running;
    Ok(())
}

fn stop_impl(handle: *mut AcxHandle) -> std::result::Result<(), AcxError> {
    if handle.is_null() {
        return Err(AcxError::Attack("handle is null".to_string()));
    }
    // SAFETY: handle was validated above.
    let handle_ref = unsafe { &*handle };
    let control = {
        let inner = lock_inner(&handle_ref.inner);
        inner.control.clone()
    };
    handle_ref.gate.close();
    if let Some(control) = control {
        control.stop();
        let mut inner = lock_inner(&handle_ref.inner);
        if matches!(inner.state, HandleState::Running | HandleState::Paused) {
            inner.state = HandleState::Stopped;
        }
    }
    Ok(())
}

fn status_impl(
    handle: *mut AcxHandle,
    info: *mut AcxStatusInfo,
) -> std::result::Result<(), AcxError> {
    if handle.is_null() {
        return Err(AcxError::Attack("handle is null".to_string()));
    }
    if info.is_null() {
        return Err(AcxError::Attack("status info is null".to_string()));
    }
    // SAFETY: caller supplies a valid status struct for the duration of the call.
    let native = unsafe { &mut *info };
    validate_layout(
        native.struct_size,
        native.version,
        size_of::<AcxStatusInfo>(),
    )?;
    // SAFETY: handle was validated above.
    let handle_ref = unsafe { &*handle };
    let inner = lock_inner(&handle_ref.inner);
    let state = if inner.state == HandleState::Running {
        match inner.control.as_ref().map(|control| control.state()) {
            Some(acx_core::scheduler::RunState::Paused) => ACX_RUN_PAUSED,
            Some(
                acx_core::scheduler::RunState::Stopping | acx_core::scheduler::RunState::Stopped,
            ) => ACX_RUN_STOPPED,
            // The control flips to Finished inside the core before the worker
            // has delivered hit/finished callbacks; keep the public state
            // Running until the worker publishes its final report.
            Some(acx_core::scheduler::RunState::Finished) | None => ACX_RUN_RUNNING,
            _ => ACX_RUN_RUNNING,
        }
    } else {
        inner.state.as_abi()
    };
    native.state = state;
    native.tried = inner.progress.tried;
    native.total = inner.progress.total;
    native.rate = inner.progress.rate;
    native.eta_sec = inner.progress.eta_sec;
    native.last_status = inner.last_status;
    Ok(())
}

fn destroy_impl(handle: *mut AcxHandle) {
    if handle.is_null() {
        return;
    }
    // SAFETY: handle was validated above and is consumed exactly once.
    let handle_ref = unsafe { &*handle };
    handle_ref.gate.close();
    if let Some(control) = {
        let inner = lock_inner(&handle_ref.inner);
        inner.control.clone()
    } {
        control.stop();
    }
    let worker = {
        let mut inner = lock_inner(&handle_ref.inner);
        inner.worker.take()
    };
    if let Some(worker) = worker {
        let _ = worker.join();
    }
    // SAFETY: handle came from Box::into_raw and is not used after this point.
    drop(unsafe { Box::from_raw(handle) });
}

/// Create one native handle. `config` may be null for defaults.
///
/// # Safety
/// `config`, when non-null, must point to a valid `AcxConfig`; `out` must be a
/// valid writable pointer for one handle pointer.
#[no_mangle]
pub unsafe extern "C" fn acx_create(config: *const AcxConfig, out: *mut *mut AcxHandle) -> i32 {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| create_impl(config, out))) {
        Ok(result) => finish(result),
        Err(_) => {
            set_last_error("Rust panic caught in acx_create");
            ACX_ERR_PANIC
        }
    }
}

/// Stop, join, and free a handle. Null is a no-op.
///
/// # Safety
/// `handle` must be null or a live handle from `acx_create` that is not used
/// again after this call.
#[no_mangle]
pub unsafe extern "C" fn acx_destroy(handle: *mut AcxHandle) {
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| destroy_impl(handle)));
}

/// Start one job on a handle. The call returns after the worker is spawned.
///
/// # Safety
/// `handle` must be live; `spec` must be a valid `AcxAttackSpec`; `callbacks`
/// must be null or a valid `AcxCallbacks` whose pointers stay valid until
/// `acx_destroy`. Callbacks must not call `acx_*` reentrantly.
#[no_mangle]
pub unsafe extern "C" fn acx_start(
    handle: *mut AcxHandle,
    spec: *const AcxAttackSpec,
    callbacks: *const AcxCallbacks,
) -> i32 {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        start_impl(handle, spec, callbacks)
    })) {
        Ok(result) => finish_handle(handle, result),
        Err(_) => {
            set_last_error("Rust panic caught in acx_start");
            ACX_ERR_PANIC
        }
    }
}

/// Pause the running job.
///
/// # Safety
/// `handle` must be null or a live handle from `acx_create`.
#[no_mangle]
pub unsafe extern "C" fn acx_pause(handle: *mut AcxHandle) -> i32 {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| pause_impl(handle))) {
        Ok(result) => finish_handle(handle, result),
        Err(_) => {
            set_last_error("Rust panic caught in acx_pause");
            ACX_ERR_PANIC
        }
    }
}

/// Resume a paused job.
///
/// # Safety
/// `handle` must be null or a live handle from `acx_create`.
#[no_mangle]
pub unsafe extern "C" fn acx_resume(handle: *mut AcxHandle) -> i32 {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| resume_impl(handle))) {
        Ok(result) => finish_handle(handle, result),
        Err(_) => {
            set_last_error("Rust panic caught in acx_resume");
            ACX_ERR_PANIC
        }
    }
}

/// Stop the job; no new callback starts after this returns.
///
/// # Safety
/// `handle` must be null or a live handle from `acx_create`.
#[no_mangle]
pub unsafe extern "C" fn acx_stop(handle: *mut AcxHandle) -> i32 {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| stop_impl(handle))) {
        Ok(result) => finish_handle(handle, result),
        Err(_) => {
            set_last_error("Rust panic caught in acx_stop");
            ACX_ERR_PANIC
        }
    }
}

/// Copy the current status into `info`.
///
/// # Safety
/// `handle` must be null or a live handle; `info` must be a valid writable
/// `AcxStatusInfo` with `struct_size`/`version` initialized.
#[no_mangle]
pub unsafe extern "C" fn acx_status(handle: *mut AcxHandle, info: *mut AcxStatusInfo) -> i32 {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| status_impl(handle, info))) {
        Ok(result) => finish_handle(handle, result),
        Err(_) => {
            set_last_error("Rust panic caught in acx_status");
            ACX_ERR_PANIC
        }
    }
}

/// Last error for the handle, or the thread-local error when handle is null.
/// The pointer is valid until the next failing call on that handle/thread.
///
/// # Safety
/// `handle` must be null or a live handle from `acx_create`.
#[no_mangle]
pub unsafe extern "C" fn acx_last_error(handle: *mut AcxHandle) -> *const c_char {
    if !handle.is_null() {
        // SAFETY: handle was supplied by the caller and is live for this call.
        let handle_ref = unsafe { &*handle };
        return lock_inner(&handle_ref.inner).last_error.as_ptr();
    }
    LAST_ERROR.with(|slot| slot.borrow().as_ptr())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn cstr(ptr: *const c_char) -> String {
        // SAFETY: tested pointers come from static C strings in this crate.
        unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned()
    }

    #[test]
    fn exposes_stable_metadata() {
        assert_eq!(acx_abi_version(), ACX_ABI_V1);
        assert_eq!(cstr(acx_product()), acx_core::PRODUCT);
        assert_eq!(cstr(acx_version()), acx_core::VERSION);
        assert_eq!(cstr(acx_status_name(ACX_OK)), "ACX_OK");
        assert_eq!(cstr(acx_status_name(99)), "ACX_ERR_UNKNOWN");
    }

    #[test]
    fn create_and_destroy_handle() {
        let mut handle: *mut AcxHandle = std::ptr::dangling_mut();
        let status = unsafe { acx_create(std::ptr::null(), &mut handle) };
        assert_eq!(status, ACX_OK);
        assert!(!handle.is_null());
        unsafe { acx_destroy(handle) };
    }

    #[test]
    fn rejects_bad_struct_layout() {
        let mut handle: *mut AcxHandle = std::ptr::null_mut();
        let config = AcxConfig {
            struct_size: 1,
            version: ACX_ABI_V1,
            reserved: [0; 4],
        };
        let status = unsafe { acx_create(&config, &mut handle) };
        assert_eq!(status, ACX_ERR_INVALID_ARG);
        assert!(handle.is_null());
        assert!(!cstr(unsafe { acx_last_error(std::ptr::null_mut()) }).is_empty());
    }

    #[test]
    fn rejects_reserved_input_kinds() {
        let mut handle: *mut AcxHandle = std::ptr::null_mut();
        assert_eq!(unsafe { acx_create(std::ptr::null(), &mut handle) }, ACX_OK);
        let path = CString::new("dummy.rar").expect("test path");
        let input = AcxInput {
            struct_size: size_of::<AcxInput>() as u32,
            version: ACX_ABI_V1,
            kind: ACX_INPUT_FD,
            path: path.as_ptr(),
            fd: -1,
            uri: std::ptr::null(),
            reserved: [0; 4],
        };
        let spec = AcxAttackSpec {
            struct_size: size_of::<AcxAttackSpec>() as u32,
            version: ACX_ABI_V1,
            input,
            mode: ACX_ATTACK_DICT,
            dictionary_path: path.as_ptr(),
            masks: std::ptr::null(),
            mask_count: 0,
            charset: std::ptr::null(),
            min_len: 0,
            max_len: 0,
            custom: [std::ptr::null(); 4],
            rules: std::ptr::null(),
            rule_count: 0,
            prefix_mask: std::ptr::null(),
            suffix_mask: std::ptr::null(),
            threads: 1,
            checkpoint_path: std::ptr::null(),
            resume: 0,
            encoding: std::ptr::null(),
            strict: 0,
            rar_no_fast_reject: 0,
            report_stats: 0,
            reserved: [0; 8],
        };
        assert_eq!(
            unsafe { acx_start(handle, &spec, std::ptr::null()) },
            ACX_ERR_UNSUPPORTED
        );
        unsafe { acx_destroy(handle) };
    }

    #[test]
    fn callback_gate_blocks_after_close() {
        let gate = CallbackGate::new();
        let calls = Arc::new(AtomicUsize::new(0));
        let callbacks = CallbackSet::default();
        let seen = Arc::clone(&calls);
        gate.invoke(&callbacks, |_| {
            seen.fetch_add(1, Ordering::SeqCst);
        });
        gate.close();
        gate.invoke(&callbacks, |_| {
            seen.fetch_add(1, Ordering::SeqCst);
        });
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
