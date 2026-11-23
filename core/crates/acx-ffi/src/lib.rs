// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 ArchCracker contributors

//! Minimal C ABI surface for M0. The attack API lands in P3.
//!
//! Contract:
//! - All returned `const char*` are static, NUL-terminated UTF-8; do not free.
//! - Functions never panic across the boundary; M0 has no fallible calls yet.

use std::ffi::c_char;

static PRODUCT_C: &[u8] = concat!("ArchCracker", "\0").as_bytes();
static VERSION_C: &[u8] = concat!(env!("CARGO_PKG_VERSION"), "\0").as_bytes();

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

/// Product name, e.g. `ArchCracker`.
#[no_mangle]
pub extern "C" fn acx_product() -> *const c_char {
    PRODUCT_C.as_ptr().cast()
}

/// Core version, e.g. `0.0.1`.
#[no_mangle]
pub extern "C" fn acx_version() -> *const c_char {
    VERSION_C.as_ptr().cast()
}

/// Stable name for a status code.
#[no_mangle]
pub extern "C" fn acx_status_name(status: i32) -> *const c_char {
    let s: &[u8] = match status {
        ACX_OK => b"ACX_OK\0",
        ACX_ERR_INVALID_ARG => b"ACX_ERR_INVALID_ARG\0",
        ACX_ERR_IO => b"ACX_ERR_IO\0",
        ACX_ERR_UNSUPPORTED => b"ACX_ERR_UNSUPPORTED\0",
        ACX_ERR_ARCHIVE => b"ACX_ERR_ARCHIVE\0",
        ACX_ERR_MISSING_VOLUME => b"ACX_ERR_MISSING_VOLUME\0",
        ACX_ERR_CANCELLED => b"ACX_ERR_CANCELLED\0",
        ACX_ERR_INTERNAL => b"ACX_ERR_INTERNAL\0",
        ACX_ERR_PANIC => b"ACX_ERR_PANIC\0",
        _ => b"ACX_ERR_UNKNOWN\0",
    };
    s.as_ptr().cast()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    #[test]
    fn exposes_version() {
        let p = acx_version();
        let s = unsafe { CStr::from_ptr(p) }.to_str().unwrap();
        assert_eq!(s, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn status_names_are_stable() {
        let p = acx_status_name(ACX_ERR_MISSING_VOLUME);
        let s = unsafe { CStr::from_ptr(p) }.to_str().unwrap();
        assert_eq!(s, "ACX_ERR_MISSING_VOLUME");
    }
}
