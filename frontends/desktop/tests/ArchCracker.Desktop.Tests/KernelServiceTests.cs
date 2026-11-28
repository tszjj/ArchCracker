// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

using ArchCracker.Desktop.Services;
using ArchCracker.Shared;

namespace ArchCracker.Desktop.Tests;

public sealed class KernelServiceTests
{
    [Fact]
    public void ProbeReportsFrozenV1Metadata()
    {
        var service = new KernelService();
        var result = service.Probe();

        Assert.True(result.Available, result.Error);
        Assert.Equal(AcxStatusKind.Ok, result.Status);
        Assert.Equal(1u, result.AbiVersion);
        Assert.False(string.IsNullOrWhiteSpace(result.Product));
        Assert.False(string.IsNullOrWhiteSpace(result.Version));
        Assert.True(File.Exists(result.LibraryPath));
    }

    [Fact]
    public void HandleLifecycleIsSafe()
    {
        var service = new KernelService();
        using var handle = service.CreateHandle();

        Assert.False(handle.IsInvalid);
        var status = service.GetStatus(handle);
        Assert.Equal(AcxRunStateKind.Idle, status.State);
        Assert.Equal(AcxStatusKind.Ok, status.LastStatus);

        service.DestroyHandle(handle);
        Assert.True(handle.IsClosed);
    }

    [Fact]
    public void DoubleDestroyIsSafe()
    {
        var service = new KernelService();
        var handle = service.CreateHandle();
        service.DestroyHandle(handle);
        service.DestroyHandle(handle);
        Assert.True(handle.IsClosed);
    }
}
