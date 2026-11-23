// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

//! Minimal C ABI surface for M0. The attack API lands in P3.
//!
//! Contract:
//! - All returned `const char*` are static, NUL-terminated UTF-8; do not free.
//! - Functions never panic across the boundary; fallible calls return a status
//!   code and write a message retrievable via the future `acx_last_error`.

use std::ffi::{c_char, CString};
use std::sync::OnceLock;

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

static PRODUCT_C: OnceLock<CString> = OnceLock::new();
static VERSION_C: OnceLock<CString> = OnceLock::new();

fn product_c() -> &'static CString {
    PRODUCT_C.get_or_init(|| CString::new(acx_core::PRODUCT).unwrap_or_default())
}

fn version_c() -> &'static CString {
    VERSION_C.get_or_init(|| CString::new(acx_core::VERSION).unwrap_or_default())
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
        ACX_ERR_UNKNOWN => b"ACX_ERR_UNKNOWN\0",
        _ => b"ACX_ERR_UNKNOWN\0",
    };
    s.as_ptr().cast()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    fn cstr(p: *const c_char) -> String {
        // SAFETY: the pointers returned by this crate point to static CStrings.
        unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()
    }

    #[test]
    fn exposes_product_and_version_from_core() {
        assert_eq!(cstr(acx_product()), acx_core::PRODUCT);
        assert_eq!(cstr(acx_version()), acx_core::VERSION);
    }

    #[test]
    fn status_names_are_stable() {
        let cases = [
            (ACX_OK, "ACX_OK"),
            (ACX_ERR_INVALID_ARG, "ACX_ERR_INVALID_ARG"),
            (ACX_ERR_IO, "ACX_ERR_IO"),
            (ACX_ERR_UNSUPPORTED, "ACX_ERR_UNSUPPORTED"),
            (ACX_ERR_ARCHIVE, "ACX_ERR_ARCHIVE"),
            (ACX_ERR_MISSING_VOLUME, "ACX_ERR_MISSING_VOLUME"),
            (ACX_ERR_CANCELLED, "ACX_ERR_CANCELLED"),
            (ACX_ERR_INTERNAL, "ACX_ERR_INTERNAL"),
            (ACX_ERR_PANIC, "ACX_ERR_PANIC"),
            (ACX_ERR_UNKNOWN, "ACX_ERR_UNKNOWN"),
        ];
        for (code, name) in cases {
            assert_eq!(cstr(acx_status_name(code)), name);
        }
        assert_eq!(cstr(acx_status_name(99)), "ACX_ERR_UNKNOWN");
    }
}
