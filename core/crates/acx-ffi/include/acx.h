/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2026 ArchCracker contributors
 *
 * ArchCracker C ABI v1 for desktop, Android (JNI) and HarmonyOS (NAPI).
 * All pointers are borrowed unless documented otherwise: the native side
 * copies strings during the call that receives them. Returned `const char*`
 * strings are owned by the library and remain valid only until the next call
 * on the same handle (or the same thread for handle-less errors).
 */
#ifndef ACX_H
#define ACX_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Bump only on breaking struct/layout changes. */
#define ACX_ABI_VERSION 1

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

typedef enum AcxInputKind {
    ACX_INPUT_PATH = 0,
    ACX_INPUT_FD = 1,
    ACX_INPUT_URI = 2
} AcxInputKind;

typedef enum AcxAttackMode {
    ACX_ATTACK_DICT = 0,
    ACX_ATTACK_MASK = 1,
    ACX_ATTACK_BRUTE = 2,
    ACX_ATTACK_HYBRID = 3
} AcxAttackMode;

typedef enum AcxRunState {
    ACX_RUN_IDLE = 0,
    ACX_RUN_RUNNING = 1,
    ACX_RUN_PAUSED = 2,
    ACX_RUN_STOPPED = 3,
    ACX_RUN_FINISHED = 4,
    ACX_RUN_FAILED = 5
} AcxRunState;

typedef struct AcxConfig {
    uint32_t struct_size;
    uint32_t version;
    uint64_t reserved[4];
} AcxConfig;

/* Full input abstraction frozen in v1. Windows uses PATH; FD/URI are reserved
 * for JNI/NAPI frontends and return ACX_ERR_UNSUPPORTED until those glue
 * layers exist. Pointers are borrowed only for the acx_start call. */
typedef struct AcxInput {
    uint32_t struct_size;
    uint32_t version;
    uint32_t kind;          /* AcxInputKind */
    const char* path;       /* ACX_INPUT_PATH, UTF-8, not NUL-free */
    intptr_t fd;            /* ACX_INPUT_FD, borrowed native handle */
    const char* uri;        /* ACX_INPUT_URI, UTF-8 */
    uint64_t reserved[4];
} AcxInput;

typedef struct AcxAttackSpec {
    uint32_t struct_size;
    uint32_t version;
    AcxInput input;
    uint32_t mode;          /* AcxAttackMode */
    const char* dictionary_path; /* DICT / HYBRID */
    const char* const* masks;    /* MASK, borrowed array */
    uint32_t mask_count;
    const char* charset;         /* BRUTE */
    uint32_t min_len;
    uint32_t max_len;
    const char* custom[4];       /* optional custom sets ?1..?4 */
    const char* const* rules;    /* HYBRID, borrowed array */
    uint32_t rule_count;
    const char* prefix_mask;     /* HYBRID */
    const char* suffix_mask;     /* HYBRID */
    uint32_t threads;            /* 0 = available parallelism */
    const char* checkpoint_path; /* nullable: <archive>.acx-checkpoint */
    uint8_t resume;
    const char* encoding;        /* nullable: auto|utf8|gbk|cp437|oem */
    uint8_t strict;
    uint8_t rar_no_fast_reject;
    uint8_t report_stats;
    uint64_t reserved[8];
} AcxAttackSpec;

typedef void (*AcxProgressFn)(void* user, uint64_t tried, uint64_t total,
                              double rate, uint64_t eta_sec);
typedef void (*AcxHitFn)(void* user, const uint8_t* password, size_t len);
typedef void (*AcxLogFn)(void* user, int32_t level, const char* message);
typedef void (*AcxFinishedFn)(void* user, int32_t status);

/* Callback functions must return quickly and must not call acx_* reentrantly.
 * User data must remain valid until acx_destroy. After acx_stop returns, no
 * further callback starts. */
typedef struct AcxCallbacks {
    uint32_t struct_size;
    uint32_t version;
    AcxProgressFn on_progress;
    AcxHitFn on_hit;
    AcxLogFn on_log;
    AcxFinishedFn on_finished;
    void* user;
    uint64_t reserved[4];
} AcxCallbacks;

typedef struct AcxStatusInfo {
    uint32_t struct_size;
    uint32_t version;
    uint32_t state;         /* AcxRunState */
    uint64_t tried;
    uint64_t total;
    double rate;            /* completed attempts per second */
    uint64_t eta_sec;
    int32_t last_status;    /* AcxStatus of the last operation */
    uint64_t reserved[4];
} AcxStatusInfo;

/* One handle owns at most one job; call acx_destroy before reusing it. */
typedef struct AcxHandle AcxHandle;

ACX_API uint32_t acx_abi_version(void);
ACX_API const char* acx_product(void);
ACX_API const char* acx_version(void);
ACX_API const char* acx_status_name(int32_t status);

ACX_API AcxStatus acx_create(const AcxConfig* config, AcxHandle** out);
ACX_API void acx_destroy(AcxHandle* handle);
ACX_API AcxStatus acx_start(AcxHandle* handle, const AcxAttackSpec* spec,
                            const AcxCallbacks* callbacks);
ACX_API AcxStatus acx_pause(AcxHandle* handle);
ACX_API AcxStatus acx_resume(AcxHandle* handle);
ACX_API AcxStatus acx_stop(AcxHandle* handle);
ACX_API AcxStatus acx_status(AcxHandle* handle, AcxStatusInfo* info);
ACX_API const char* acx_last_error(AcxHandle* handle);

#ifdef __cplusplus
}
#endif

#endif /* ACX_H */
