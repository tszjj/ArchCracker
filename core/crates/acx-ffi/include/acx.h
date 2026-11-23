/* SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2026 ArchCracker contributors
 *
 * Minimal C ABI for M0. The attack API is added in P3 (see docs/roadmap.md).
 * All returned `const char*` are static, NUL-terminated UTF-8; do not free.
 */
#ifndef ACX_H
#define ACX_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ABI revision; bump on breaking struct/layout changes. */
#define ACX_ABI_VERSION 0

#if defined(_WIN32) && defined(ACX_SHARED)
#  if defined(ACX_BUILD)
#    define ACX_API __declspec(dllexport)
#  else
#    define ACX_API __declspec(dllimport)
#  endif
#else
#  define ACX_API
#endif

typedef enum AcxStatus {
    ACX_OK = 0,
    ACX_ERR_INVALID_ARG = 1,
    ACX_ERR_IO = 2,
    ACX_ERR_UNSUPPORTED = 3,
    ACX_ERR_ARCHIVE = 4,
    ACX_ERR_MISSING_VOLUME = 5,
    ACX_ERR_CANCELLED = 6,
    ACX_ERR_INTERNAL = 7,
    ACX_ERR_PANIC = 8,
    ACX_ERR_UNKNOWN = 9
} AcxStatus;

ACX_API const char* acx_product(void);
ACX_API const char* acx_version(void);
ACX_API const char* acx_status_name(int32_t status);

#ifdef __cplusplus
}
#endif

#endif /* ACX_H */
