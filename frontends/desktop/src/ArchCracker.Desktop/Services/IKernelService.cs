// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

using ArchCracker.Shared;
using ArchCracker.Desktop.Models;
using ArchCracker.Desktop.Native;

namespace ArchCracker.Desktop.Services;

public interface IKernelService
{
    string LibraryPath { get; }
    KernelProbeResult Probe();
    AcxInspectionInfo Inspect(string path);
    AcxJobHandle CreateHandle();
    void DestroyHandle(AcxJobHandle handle);
    JobStatusSnapshot GetStatus(AcxJobHandle handle);
    AcxStatusKind Start(AcxJobHandle handle, in AcxAttackSpec spec, in AcxCallbacks callbacks);
    AcxStatusKind Pause(AcxJobHandle handle);
    AcxStatusKind Resume(AcxJobHandle handle);
    AcxStatusKind Stop(AcxJobHandle handle);
    AcxEstimateInfo Estimate(in AcxAttackSpec spec);
}
