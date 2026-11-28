// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using ArchCracker.Desktop.Services;

namespace ArchCracker.Desktop.Native;

public interface INativeCallbackSink
{
    void OnProgress(ulong tried, ulong total, double rate, ulong etaSec);
    void OnHit(byte[] password);
    void OnLog(int level, string message);
    void OnFinished(int status);
}

/// <summary>
/// Owns the unmanaged function pointers and the GCHandle used as callback user
/// data. This type does not reference Avalonia; UI marshalling is a service.
/// </summary>
public sealed unsafe class AcxCallbackBridge : IDisposable, INativeCallbackProvider
{
    private const int MaxHitBytes = 4096;

    private GCHandle _sinkHandle;
    private bool _disposed;

    public AcxCallbacks Callbacks { get; }

    public AcxCallbackBridge(INativeCallbackSink sink)
    {
        _sinkHandle = GCHandle.Alloc(sink, GCHandleType.Normal);
        var user = GCHandle.ToIntPtr(_sinkHandle);
        Callbacks = new AcxCallbacks
        {
            StructSize = (uint)sizeof(AcxCallbacks),
            Version = 1,
            OnProgress = (IntPtr)(delegate* unmanaged[Cdecl]<IntPtr, ulong, ulong, double, ulong, void>)&OnProgress,
            OnHit = (IntPtr)(delegate* unmanaged[Cdecl]<IntPtr, IntPtr, nuint, void>)&OnHit,
            OnLog = (IntPtr)(delegate* unmanaged[Cdecl]<IntPtr, int, IntPtr, void>)&OnLog,
            OnFinished = (IntPtr)(delegate* unmanaged[Cdecl]<IntPtr, int, void>)&OnFinished,
            User = user,
        };
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (_sinkHandle.IsAllocated) _sinkHandle.Free();
    }

    private static INativeCallbackSink? Sink(IntPtr user) =>
        GCHandle.FromIntPtr(user).Target as INativeCallbackSink;

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void OnProgress(IntPtr user, ulong tried, ulong total, double rate, ulong etaSec)
    {
        try { Sink(user)?.OnProgress(tried, total, rate, etaSec); }
        catch { /* exceptions must never cross the C ABI boundary */ }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void OnHit(IntPtr user, IntPtr password, nuint len)
    {
        try
        {
            if (len == 0 || len > MaxHitBytes) return;
            var bytes = new byte[(int)len];
            Marshal.Copy(password, bytes, 0, bytes.Length);
            Sink(user)?.OnHit(bytes);
        }
        catch { /* exceptions must never cross the C ABI boundary */ }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void OnLog(IntPtr user, int level, IntPtr message)
    {
        try { Sink(user)?.OnLog(level, AcxNative.CopyUtf8(message)); }
        catch { /* exceptions must never cross the C ABI boundary */ }
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void OnFinished(IntPtr user, int status)
    {
        try { Sink(user)?.OnFinished(status); }
        catch { /* exceptions must never cross the C ABI boundary */ }
    }
}
