/* SPDX-License-Identifier: GPL-3.0-only
 * Copyright (C) 2026 ArchCracker contributors
 *
 * Compile-only smoke test: the header must be valid C99 and C++.
 * CI builds this file with gcc/clang; it is not linked into the product.
 */
#include "acx.h"

int acx_header_smoke(void) {
    AcxStatus s = ACX_ERR_MISSING_VOLUME;
    (void)s;
    (void)ACX_ABI_VERSION;
    return (int)ACX_ERR_UNKNOWN + (acx_version() != 0) + (acx_product() != 0);
}
