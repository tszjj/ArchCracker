// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

//! End-to-end C ABI v1 test: create → start → status → callbacks → destroy.

use acx::{
    acx_abi_version, acx_create, acx_destroy, acx_estimate, acx_last_error, acx_pause, acx_resume,
    acx_start, acx_status, acx_stop, AcxAttackSpec, AcxCallbacks, AcxConfig, AcxEstimateInfo,
    AcxHandle, AcxInput, AcxStatusInfo, ACX_ERR_INVALID_ARG, ACX_ERR_IO, ACX_OK, ACX_RUN_FINISHED,
    ACX_RUN_IDLE, ACX_RUN_PAUSED, ACX_RUN_RUNNING, ACX_RUN_STOPPED,
};
use std::ffi::{c_char, c_void, CStr, CString};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use zip::unstable::write::FileOptionsExt;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

const PASSWORD: &str = "P@ssw0rd123";
const HELLO: &[u8] = b"C ABI v1 integration fixture";

fn scratch_dir() -> PathBuf {
    let unique = format!(
        "acx-cabi-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or(0)
    );
    let preferred = std::env::temp_dir().join(unique);
    if std::fs::create_dir_all(&preferred).is_ok() {
        return preferred;
    }
    let mut fallback = std::env::current_exe().unwrap_or_default();
    fallback.pop();
    fallback.pop();
    fallback.push(format!(
        "acx-cabi-tmp-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&fallback).expect("create fallback scratch dir");
    fallback
}

fn write_zip(path: &Path) {
    let file = std::fs::File::create(path).expect("create fixture archive");
    let mut writer = ZipWriter::new(file);
    let options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .with_deprecated_encryption(PASSWORD.as_bytes())
        .expect("ZipCrypto options");
    writer
        .start_file("hello.txt", options)
        .expect("start entry");
    writer.write_all(HELLO).expect("write entry");
    writer.finish().expect("finish archive");
}

fn cstr(ptr: *const c_char) -> String {
    // SAFETY: library-owned strings are valid until the next failing call.
    unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned()
}

struct Capture {
    hits: std::sync::Mutex<Vec<Vec<u8>>>,
    progress: AtomicUsize,
    logs: AtomicUsize,
    finished: AtomicUsize,
    status: AtomicUsize,
}

unsafe extern "C" fn on_progress(
    user: *mut c_void,
    _tried: u64,
    _total: u64,
    _rate: f64,
    _eta: u64,
) {
    // SAFETY: user pointer is a live Capture until acx_destroy returns.
    unsafe { &*user.cast::<Capture>() }
        .progress
        .fetch_add(1, Ordering::SeqCst);
}

unsafe extern "C" fn on_hit(user: *mut c_void, password: *const u8, len: usize) {
    // SAFETY: password bytes are valid for the duration of this callback.
    let bytes = unsafe { std::slice::from_raw_parts(password, len) }.to_vec();
    // SAFETY: user pointer is a live Capture until acx_destroy returns.
    let capture = unsafe { &*user.cast::<Capture>() };
    if let Ok(mut hits) = capture.hits.lock() {
        hits.push(bytes);
    }
    capture.finished.fetch_add(1, Ordering::SeqCst);
}

unsafe extern "C" fn on_log(user: *mut c_void, level: i32, message: *const c_char) {
    let _ = level;
    let _ = cstr(message);
    // SAFETY: user pointer is a live Capture until acx_destroy returns.
    unsafe { &*user.cast::<Capture>() }
        .logs
        .fetch_add(1, Ordering::SeqCst);
}

unsafe extern "C" fn on_finished(user: *mut c_void, status: i32) {
    // SAFETY: user pointer is a live Capture until acx_destroy returns.
    unsafe { &*user.cast::<Capture>() }
        .status
        .store(status as usize, Ordering::SeqCst);
}

#[test]
fn c_abi_v1_runs_dictionary_attack() {
    assert_eq!(acx_abi_version(), 1);
    let dir = scratch_dir();
    let archive = dir.join("fixture.zip");
    let dictionary = dir.join("dict.txt");
    let checkpoint = dir.join("run.acx-checkpoint");
    write_zip(&archive);
    std::fs::write(&dictionary, format!("wrong-one\n{PASSWORD}\n")).expect("write dictionary");

    let archive_c = CString::new(archive.to_string_lossy().as_bytes()).expect("archive string");
    let dictionary_c = CString::new(dictionary.to_string_lossy().as_bytes()).expect("dict string");
    let checkpoint_c =
        CString::new(checkpoint.to_string_lossy().as_bytes()).expect("checkpoint string");

    let input = AcxInput {
        struct_size: std::mem::size_of::<AcxInput>() as u32,
        version: 1,
        kind: 0,
        path: archive_c.as_ptr(),
        fd: -1,
        uri: std::ptr::null(),
        reserved: [0; 4],
    };
    let spec = AcxAttackSpec {
        struct_size: std::mem::size_of::<AcxAttackSpec>() as u32,
        version: 1,
        input,
        mode: 0,
        dictionary_path: dictionary_c.as_ptr(),
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
        threads: 2,
        checkpoint_path: checkpoint_c.as_ptr(),
        resume: 0,
        encoding: std::ptr::null(),
        strict: 0,
        rar_no_fast_reject: 0,
        report_stats: 1,
        reserved: [0; 8],
    };

    let capture = Box::new(Capture {
        hits: std::sync::Mutex::new(Vec::new()),
        progress: AtomicUsize::new(0),
        logs: AtomicUsize::new(0),
        finished: AtomicUsize::new(0),
        status: AtomicUsize::new(usize::MAX),
    });
    let user = Box::into_raw(capture).cast::<c_void>();
    let callbacks = AcxCallbacks {
        struct_size: std::mem::size_of::<AcxCallbacks>() as u32,
        version: 1,
        on_progress: Some(on_progress),
        on_hit: Some(on_hit),
        on_log: Some(on_log),
        on_finished: Some(on_finished),
        user,
        reserved: [0; 4],
    };

    let config = AcxConfig {
        struct_size: std::mem::size_of::<AcxConfig>() as u32,
        version: 1,
        reserved: [0; 4],
    };
    let mut estimate = AcxEstimateInfo {
        struct_size: std::mem::size_of::<AcxEstimateInfo>() as u32,
        version: 1,
        ..Default::default()
    };
    assert_eq!(unsafe { acx_estimate(&spec, &mut estimate) }, ACX_OK);
    assert!(estimate.total_low >= 2);
    assert!(estimate.measured_rate > 0.0);

    let mut handle: *mut AcxHandle = std::ptr::null_mut();
    assert_eq!(unsafe { acx_create(&config, &mut handle) }, ACX_OK);
    assert_eq!(unsafe { acx_start(handle, &spec, &callbacks) }, ACX_OK);

    let mut info = AcxStatusInfo {
        struct_size: std::mem::size_of::<AcxStatusInfo>() as u32,
        version: 1,
        state: 0,
        tried: 0,
        total: 0,
        rate: 0.0,
        eta_sec: 0,
        last_status: ACX_OK,
        reserved: [0; 4],
    };
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        assert_eq!(unsafe { acx_status(handle, &mut info) }, ACX_OK);
        if info.state != 1 && info.state != 2 {
            break;
        }
        assert!(Instant::now() < deadline, "C ABI attack timed out");
        std::thread::sleep(Duration::from_millis(25));
    }

    assert_eq!(
        info.state,
        ACX_RUN_FINISHED,
        "state={} status={} error={}",
        info.state,
        info.last_status,
        cstr(unsafe { acx_last_error(handle) })
    );
    assert_eq!(info.last_status, ACX_OK);
    assert!(
        info.total >= 2,
        "state={} status={} tried={} total={} rate={} eta={}",
        info.state,
        info.last_status,
        info.tried,
        info.total,
        info.rate,
        info.eta_sec
    );
    assert!(!unsafe { acx_last_error(handle) }.is_null());

    let capture = unsafe { Box::from_raw(user.cast::<Capture>()) };
    let hits = capture.hits.lock().expect("lock hits");
    assert_eq!(hits.len(), 1, "hits: {hits:?}");
    assert_eq!(hits[0], PASSWORD.as_bytes());
    drop(hits);
    assert!(
        capture.progress.load(Ordering::SeqCst) >= 1,
        "final progress snapshot must be delivered"
    );
    assert_eq!(
        capture.status.load(Ordering::SeqCst),
        ACX_OK as usize,
        "on_finished must be delivered exactly once"
    );

    unsafe { acx_destroy(handle) };
    let _ = std::fs::remove_dir_all(&dir);
}

struct TestJob {
    _dir: PathBuf,
    archive: CString,
    dictionary: CString,
    checkpoint: CString,
}

fn test_job() -> TestJob {
    let dir = scratch_dir();
    let archive_path = dir.join("fixture.zip");
    let dictionary_path = dir.join("dict.txt");
    write_zip(&archive_path);
    std::fs::write(&dictionary_path, format!("wrong-one\n{PASSWORD}\n")).expect("dict");
    TestJob {
        archive: CString::new(archive_path.to_string_lossy().as_bytes()).expect("archive cstr"),
        dictionary: CString::new(dictionary_path.to_string_lossy().as_bytes()).expect("dict cstr"),
        checkpoint: CString::new(dir.join("job.checkpoint").to_string_lossy().as_bytes())
            .expect("checkpoint cstr"),
        _dir: dir,
    }
}

fn job_spec(job: &TestJob, mode: u32, charset: Option<&CString>) -> AcxAttackSpec {
    let input = AcxInput {
        struct_size: std::mem::size_of::<AcxInput>() as u32,
        version: 1,
        kind: 0,
        path: job.archive.as_ptr(),
        fd: -1,
        uri: std::ptr::null(),
        reserved: [0; 4],
    };
    AcxAttackSpec {
        struct_size: std::mem::size_of::<AcxAttackSpec>() as u32,
        version: 1,
        input,
        mode,
        dictionary_path: job.dictionary.as_ptr(),
        masks: std::ptr::null(),
        mask_count: 0,
        charset: charset.map_or(std::ptr::null(), |value| value.as_ptr()),
        min_len: 1,
        max_len: 4,
        custom: [std::ptr::null(); 4],
        rules: std::ptr::null(),
        rule_count: 0,
        prefix_mask: std::ptr::null(),
        suffix_mask: std::ptr::null(),
        threads: 1,
        checkpoint_path: job.checkpoint.as_ptr(),
        resume: 0,
        encoding: std::ptr::null(),
        strict: 0,
        rar_no_fast_reject: 0,
        report_stats: 1,
        reserved: [0; 8],
    }
}

static STOP_FINISHED: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn on_finished_null(_user: *mut c_void, status: i32) {
    assert_eq!(status, ACX_OK);
    STOP_FINISHED.fetch_add(1, Ordering::SeqCst);
}

fn stop_callbacks() -> AcxCallbacks {
    STOP_FINISHED.store(0, Ordering::SeqCst);
    AcxCallbacks {
        struct_size: std::mem::size_of::<AcxCallbacks>() as u32,
        version: 1,
        on_progress: None,
        on_hit: None,
        on_log: None,
        on_finished: Some(on_finished_null),
        user: std::ptr::null_mut(),
        reserved: [0; 4],
    }
}

fn wait_for_state(handle: *mut AcxHandle, wanted: u32) -> AcxStatusInfo {
    let mut info = AcxStatusInfo {
        struct_size: std::mem::size_of::<AcxStatusInfo>() as u32,
        version: 1,
        ..Default::default()
    };
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        assert_eq!(unsafe { acx_status(handle, &mut info) }, ACX_OK);
        if info.state == wanted {
            return info;
        }
        assert!(Instant::now() < deadline, "state {wanted} not reached");
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn stop_suppresses_progress_and_hit_callbacks() {
    let job = test_job();
    let charset = CString::new("abcdefghijklmnopqrstuvwxyz").expect("charset");
    let spec = job_spec(&job, 2, Some(&charset));
    let config = AcxConfig {
        struct_size: std::mem::size_of::<AcxConfig>() as u32,
        version: 1,
        reserved: [0; 4],
    };
    let callbacks = stop_callbacks();
    let mut handle = std::ptr::null_mut();
    assert_eq!(unsafe { acx_create(&config, &mut handle) }, ACX_OK);
    assert_eq!(unsafe { acx_start(handle, &spec, &callbacks) }, ACX_OK);
    std::thread::sleep(Duration::from_millis(80));
    assert_eq!(unsafe { acx_stop(handle) }, ACX_OK);
    let info = wait_for_state(handle, ACX_RUN_STOPPED);
    assert_eq!(info.last_status, ACX_OK);
    let deadline = Instant::now() + Duration::from_secs(5);
    while STOP_FINISHED.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(STOP_FINISHED.load(Ordering::SeqCst), 1);
    unsafe { acx_destroy(handle) };
}

#[test]
fn pause_resume_and_duplicate_start() {
    let job = test_job();
    let charset = CString::new("abcdefghijklmnopqrstuvwxyz").expect("charset");
    let spec = job_spec(&job, 2, Some(&charset));
    let config = AcxConfig {
        struct_size: std::mem::size_of::<AcxConfig>() as u32,
        version: 1,
        reserved: [0; 4],
    };
    let mut handle = std::ptr::null_mut();
    assert_eq!(unsafe { acx_create(&config, &mut handle) }, ACX_OK);
    assert_eq!(
        unsafe { acx_start(handle, &spec, std::ptr::null()) },
        ACX_OK
    );
    assert_eq!(
        unsafe { acx_start(handle, &spec, std::ptr::null()) },
        ACX_ERR_INVALID_ARG
    );
    assert_eq!(unsafe { acx_pause(handle) }, ACX_OK);
    let _ = wait_for_state(handle, ACX_RUN_PAUSED);
    assert_eq!(unsafe { acx_resume(handle) }, ACX_OK);
    let mut info = AcxStatusInfo {
        struct_size: std::mem::size_of::<AcxStatusInfo>() as u32,
        version: 1,
        ..Default::default()
    };
    assert_eq!(unsafe { acx_status(handle, &mut info) }, ACX_OK);
    assert_eq!(info.state, ACX_RUN_RUNNING);
    assert_eq!(unsafe { acx_stop(handle) }, ACX_OK);
    let _ = wait_for_state(handle, ACX_RUN_STOPPED);
    unsafe { acx_destroy(handle) };
}

#[test]
fn stop_before_start_claims_gate() {
    let job = test_job();
    let spec = job_spec(&job, 0, None);
    let config = AcxConfig {
        struct_size: std::mem::size_of::<AcxConfig>() as u32,
        version: 1,
        reserved: [0; 4],
    };
    let mut handle = std::ptr::null_mut();
    assert_eq!(unsafe { acx_create(&config, &mut handle) }, ACX_OK);
    assert_eq!(unsafe { acx_stop(handle) }, ACX_OK);
    assert_eq!(
        unsafe { acx_start(handle, &spec, std::ptr::null()) },
        ACX_ERR_INVALID_ARG
    );
    unsafe { acx_destroy(handle) };
}

#[test]
fn archive_error_maps_to_status() {
    let job = test_job();
    let mut spec = job_spec(&job, 0, None);
    let missing = CString::new("definitely-missing-archive.zip").expect("missing path");
    spec.input.path = missing.as_ptr();
    let config = AcxConfig {
        struct_size: std::mem::size_of::<AcxConfig>() as u32,
        version: 1,
        reserved: [0; 4],
    };
    let mut handle = std::ptr::null_mut();
    assert_eq!(unsafe { acx_create(&config, &mut handle) }, ACX_OK);
    assert_eq!(
        unsafe { acx_start(handle, &spec, std::ptr::null()) },
        ACX_ERR_IO
    );
    let mut info = AcxStatusInfo {
        struct_size: std::mem::size_of::<AcxStatusInfo>() as u32,
        version: 1,
        ..Default::default()
    };
    assert_eq!(unsafe { acx_status(handle, &mut info) }, ACX_OK);
    assert_eq!(info.state, ACX_RUN_IDLE);
    unsafe { acx_destroy(handle) };
}
