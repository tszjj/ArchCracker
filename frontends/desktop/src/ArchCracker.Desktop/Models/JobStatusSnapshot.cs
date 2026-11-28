// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

using ArchCracker.Shared;

namespace ArchCracker.Desktop.Models;

public sealed record JobStatusSnapshot(
    AcxRunStateKind State,
    ulong Tried,
    ulong Total,
    double Rate,
    ulong EtaSec,
    AcxStatusKind LastStatus);
