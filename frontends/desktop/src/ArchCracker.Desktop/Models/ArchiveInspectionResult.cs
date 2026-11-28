// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

using ArchCracker.Desktop.Native;
using ArchCracker.Shared;

namespace ArchCracker.Desktop.Models;

public sealed record ArchiveInspectionResult(
    bool Success,
    AcxStatusKind Status,
    AcxInspectionInfo Info,
    string Error);
