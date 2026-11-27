/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2026 ArchCracker contributors
 *
 * Compile-only smoke test for acx.h under C99 and C++17. It checks that all
 * v1 structs/functions are visible and that the ABI version is 1.
 */
#include "acx.h"

#include <stddef.h>
#include <stdint.h>

/* Frozen v1 layout sizes; keep in sync with acx-ffi/src/lib.rs. */
#ifdef __cplusplus
#define ASSERT_SIZE(type, expected) static_assert(sizeof(type) == (expected), #type " size")
#else
#define ASSERT_SIZE(type, expected) typedef char assert_size_##type[(sizeof(type) == (expected)) ? 1 : -1]
#endif
ASSERT_SIZE(AcxConfig, 40);
ASSERT_SIZE(AcxInput, 72);
ASSERT_SIZE(AcxAttackSpec, 296);
ASSERT_SIZE(AcxCallbacks, 80);
ASSERT_SIZE(AcxStatusInfo, 88);
ASSERT_SIZE(AcxEstimateInfo, 112);

static void noop_progress(void* user, uint64_t tried, uint64_t total,
                          double rate, uint64_t eta_sec) {
    (void)user; (void)tried; (void)total; (void)rate; (void)eta_sec;
}

static void noop_hit(void* user, const uint8_t* password, size_t len) {
    (void)user; (void)password; (void)len;
}

static void noop_log(void* user, int32_t level, const char* message) {
    (void)user; (void)level; (void)message;
}

static void noop_finished(void* user, int32_t status) {
    (void)user; (void)status;
}

int acx_header_smoke(void) {
    AcxConfig config;
    AcxInput input;
    AcxAttackSpec spec;
    AcxCallbacks callbacks;
    AcxStatusInfo status;
    AcxEstimateInfo estimate;
    AcxHandle* handle = 0;
    int rc;

    config.struct_size = (uint32_t)sizeof(config);
    config.version = 1;
    for (int i = 0; i < 4; ++i) config.reserved[i] = 0;

    input.struct_size = (uint32_t)sizeof(input);
    input.version = 1;
    input.kind = ACX_INPUT_PATH;
    input.path = "fixture.zip";
    input.fd = -1;
    input.uri = 0;
    for (int i = 0; i < 4; ++i) input.reserved[i] = 0;

    spec.struct_size = (uint32_t)sizeof(spec);
    spec.version = 1;
    spec.input = input;
    spec.mode = ACX_ATTACK_DICT;
    spec.dictionary_path = "dict.txt";
    spec.masks = 0;
    spec.mask_count = 0;
    spec.charset = 0;
    spec.min_len = 0;
    spec.max_len = 0;
    for (int i = 0; i < 4; ++i) spec.custom[i] = 0;
    spec.rules = 0;
    spec.rule_count = 0;
    spec.prefix_mask = 0;
    spec.suffix_mask = 0;
    spec.threads = 1;
    spec.checkpoint_path = 0;
    spec.resume = 0;
    spec.encoding = 0;
    spec.strict = 0;
    spec.rar_no_fast_reject = 0;
    spec.report_stats = 1;
    for (int i = 0; i < 8; ++i) spec.reserved[i] = 0;

    callbacks.struct_size = (uint32_t)sizeof(callbacks);
    callbacks.version = 1;
    callbacks.on_progress = noop_progress;
    callbacks.on_hit = noop_hit;
    callbacks.on_log = noop_log;
    callbacks.on_finished = noop_finished;
    callbacks.user = 0;
    for (int i = 0; i < 4; ++i) callbacks.reserved[i] = 0;

    status.struct_size = (uint32_t)sizeof(status);
    status.version = 1;
    estimate.struct_size = (uint32_t)sizeof(estimate);
    estimate.version = 1;

    /* Exercise pointer types without linking the native library. */
    (void)&spec;
    (void)&callbacks;
    (void)&status;
    (void)&estimate;

    rc = acx_abi_version() == ACX_ABI_VERSION ? 0 : 1;
    if (rc != 0) return rc;
    if (acx_create(&config, &handle) != ACX_OK) return 2;
    if (handle) {
        rc = acx_status(handle, &status);
        acx_destroy(handle);
        if (rc != ACX_OK) return rc;
    }
    return 0;
}
