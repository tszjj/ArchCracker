/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2026 ArchCracker contributors
 *
 * Compile-only smoke test: the v1 header must be valid C99 and C++17.
 * CI compiles this file with -Wall -Wextra -Werror; it is not linked.
 */
#include "acx.h"

static void acx_smoke_callback(void* user, uint64_t tried, uint64_t total,
                               double rate, uint64_t eta_sec) {
    (void)user;
    (void)tried;
    (void)total;
    (void)rate;
    (void)eta_sec;
}

int acx_header_smoke(void) {
    AcxStatus status = ACX_ERR_UNKNOWN;
    AcxConfig config;
    AcxInput input;
    AcxAttackSpec spec;
    AcxCallbacks callbacks;
    AcxStatusInfo info;
    AcxHandle* handle = 0;

    config.struct_size = (uint32_t)sizeof(AcxConfig);
    config.version = ACX_ABI_VERSION;
    config.reserved[0] = 0;

    input.struct_size = (uint32_t)sizeof(AcxInput);
    input.version = ACX_ABI_VERSION;
    input.kind = ACX_INPUT_PATH;
    input.path = "archive.zip";
    input.fd = 0;
    input.uri = 0;
    input.reserved[0] = 0;

    spec.struct_size = (uint32_t)sizeof(AcxAttackSpec);
    spec.version = ACX_ABI_VERSION;
    spec.input = input;
    spec.mode = ACX_ATTACK_DICT;
    spec.dictionary_path = "dict.txt";
    spec.masks = 0;
    spec.mask_count = 0;
    spec.charset = 0;
    spec.min_len = 0;
    spec.max_len = 0;
    spec.reserved[0] = 0;

    callbacks.struct_size = (uint32_t)sizeof(AcxCallbacks);
    callbacks.version = ACX_ABI_VERSION;
    callbacks.on_progress = acx_smoke_callback;
    callbacks.on_hit = 0;
    callbacks.on_log = 0;
    callbacks.on_finished = 0;
    callbacks.user = 0;
    callbacks.reserved[0] = 0;

    info.struct_size = (uint32_t)sizeof(AcxStatusInfo);
    info.version = ACX_ABI_VERSION;
    info.state = ACX_RUN_IDLE;
    info.tried = 0;
    info.total = 0;
    info.rate = 0.0;
    info.eta_sec = 0;
    info.last_status = ACX_OK;
    info.reserved[0] = 0;

    /* Exercise pointer types without linking the native library. */
    (void)&spec;
    (void)&callbacks;

    status = acx_create(&config, &handle);
    if (status == ACX_OK) {
        status = acx_status(handle, &info);
        acx_destroy(handle);
    }

    return (int)status + (int)acx_abi_version() - (int)ACX_ABI_VERSION
           + (acx_version() != 0) + (acx_product() != 0);
}
