// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

using ArchCracker.Desktop.Native;
using ArchCracker.Shared;

namespace ArchCracker.Desktop.Models;

public sealed record KernelProbeResult(
    bool Available,
    string Product,
    string Version,
    uint AbiVersion,
    string LibraryPath,
    AcxStatusKind Status,
    string Error,
    AcxLibraryIntegrity Integrity);
