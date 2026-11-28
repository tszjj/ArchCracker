// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

using ArchCracker.Desktop.Models;
using ArchCracker.Desktop.Native;
using ArchCracker.Shared;

namespace ArchCracker.Desktop.Services;

public sealed class KernelService : IKernelService
{
    private readonly string? _loadError;

    public KernelService(string? libraryPath = null)
    {
        try
        {
            LibraryPath = AcxNative.ResolveLibraryPath(libraryPath);
            AcxNative.Configure(LibraryPath);
            Integrity = AcxNative.VerifyLibrary(LibraryPath);
            if (Integrity == AcxLibraryIntegrity.Mismatch)
                throw new InvalidDataException($"Native library hash mismatch: {LibraryPath}.sha256");
        }
        catch (Exception ex)
        {
            LibraryPath = libraryPath ?? Path.Combine(AppContext.BaseDirectory, "acx.dll");
            _loadError = ex.Message;
        }
    }

    public string LibraryPath { get; }

    public AcxLibraryIntegrity Integrity { get; private set; } = AcxLibraryIntegrity.NotPinned;

    public KernelProbeResult Probe()
    {
        if (_loadError is not null)
        {
            return new KernelProbeResult(false, string.Empty, string.Empty, 0, LibraryPath,
                AcxStatusKind.Internal, _loadError, Integrity);
        }

        try
        {
            var abi = AcxNative.AbiVersion();
            var product = AcxNative.CopyUtf8(AcxNative.Product());
            var version = AcxNative.CopyUtf8(AcxNative.Version());
            if (abi != AcxNative.ExpectedAbiVersion)
            {
                return new KernelProbeResult(false, product, version, abi, LibraryPath,
                    AcxStatusKind.Unsupported, $"ABI mismatch: expected {AcxNative.ExpectedAbiVersion}, got {abi}", Integrity);
            }

            using var handle = CreateHandle();
            return new KernelProbeResult(true, product, version, abi, LibraryPath, AcxStatusKind.Ok, string.Empty, Integrity);
        }
        catch (Exception ex)
        {
            return new KernelProbeResult(false, string.Empty, string.Empty, 0, LibraryPath,
                AcxStatusKind.Internal, ex.Message, Integrity);
        }
    }

    public ArchiveInspectionResult Inspect(string path)
    {
        var info = AcxInspectionInfo.Create();
        var code = AcxNative.Inspect(path, ref info);
        var status = AcxStatusMap.FromCode(code);
        var error = status == AcxStatusKind.Ok
            ? string.Empty
            : AcxNative.CopyUtf8(AcxNative.LastError(IntPtr.Zero));
        return new ArchiveInspectionResult(status == AcxStatusKind.Ok, status, info, error);
    }

    public AcxJobHandle CreateHandle()
    {
        var config = AcxConfig.Create();
        var status = AcxNative.Create(config, out var raw);
        if (status != (int)AcxStatusKind.Ok)
        {
            var message = AcxNative.CopyUtf8(AcxNative.LastError(IntPtr.Zero));
            throw new InvalidOperationException($"acx_create failed ({status}): {message}");
        }
        return new AcxJobHandle(raw);
    }

    public void DestroyHandle(AcxJobHandle handle) => handle.Dispose();

    public JobStatusSnapshot GetStatus(AcxJobHandle handle)
    {
        var info = AcxStatusInfo.Create();
        var status = AcxNative.Status(handle, ref info);
        if (status != (int)AcxStatusKind.Ok)
        {
            var message = AcxNative.CopyUtf8(AcxNative.LastError(handle.DangerousGetHandle()));
            throw new InvalidOperationException($"acx_status failed ({status}): {message}");
        }
        return new JobStatusSnapshot(
            AcxStatusMap.RunStateFromCode(info.State),
            info.Tried,
            info.Total,
            info.Rate,
            info.EtaSec,
            AcxStatusMap.FromCode(info.LastStatus));
    }

    public AcxStatusKind Start(AcxJobHandle handle, in AcxAttackSpec spec, in AcxCallbacks callbacks)
    {
        var status = AcxNative.Start(handle, spec, callbacks);
        return FailIfNotOk("acx_start", status, handle);
    }

    public AcxStatusKind Pause(AcxJobHandle handle) => FailIfNotOk("acx_pause", AcxNative.Pause(handle), handle);

    public AcxStatusKind Resume(AcxJobHandle handle) => FailIfNotOk("acx_resume", AcxNative.Resume(handle), handle);

    public AcxStatusKind Stop(AcxJobHandle handle) => FailIfNotOk("acx_stop", AcxNative.Stop(handle), handle);

    public AcxEstimateInfo Estimate(in AcxAttackSpec spec)
    {
        var info = AcxEstimateInfo.Create();
        var status = AcxNative.Estimate(spec, ref info);
        if (status != (int)AcxStatusKind.Ok)
        {
            var message = AcxNative.CopyUtf8(AcxNative.LastError(IntPtr.Zero));
            throw new InvalidOperationException($"acx_estimate failed ({status}): {message}");
        }
        return info;
    }

    private static AcxStatusKind FailIfNotOk(string api, int status, AcxJobHandle handle)
    {
        var kind = AcxStatusMap.FromCode(status);
        if (kind != AcxStatusKind.Ok)
        {
            var message = AcxNative.CopyUtf8(AcxNative.LastError(handle.DangerousGetHandle()));
            throw new InvalidOperationException($"{api} failed ({status}): {message}");
        }
        return kind;
    }
}
