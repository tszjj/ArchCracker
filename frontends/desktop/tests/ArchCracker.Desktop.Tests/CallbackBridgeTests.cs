// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using ArchCracker.Desktop.Native;

namespace ArchCracker.Desktop.Tests;

public sealed class CallbackBridgeTests
{
    [Fact]
    public unsafe void ProductionBridgeDeliversAllCallbackKinds()
    {
        var sink = new RecordingSink();
        using var bridge = new AcxCallbackBridge(sink);

        Assert.NotEqual(IntPtr.Zero, bridge.Callbacks.OnProgress);
        Assert.NotEqual(IntPtr.Zero, bridge.Callbacks.OnHit);
        Assert.NotEqual(IntPtr.Zero, bridge.Callbacks.OnLog);
        Assert.NotEqual(IntPtr.Zero, bridge.Callbacks.OnFinished);
        Assert.NotEqual(IntPtr.Zero, bridge.Callbacks.User);

        InvokeProgress(bridge.Callbacks, 1, 2, 3.0, 4);
        InvokeHit(bridge.Callbacks, new byte[] { 0x41, 0x42 });
        InvokeLog(bridge.Callbacks, 2, "message");
        InvokeFinished(bridge.Callbacks, 0);

        Assert.Equal(1, sink.Progress);
        Assert.Equal("4142", sink.Hit);
        Assert.Equal("[2] message", sink.Log);
        Assert.Equal(0, sink.Finished);
    }

    [Fact]
    public unsafe void BridgeDisposeIsIdempotent()
    {
        var bridge = new AcxCallbackBridge(new RecordingSink());
        bridge.Dispose();
        bridge.Dispose();
    }

    private static unsafe void InvokeProgress(AcxCallbacks callbacks, ulong tried, ulong total, double rate, ulong etaSec)
    {
        var callback = (delegate* unmanaged[Cdecl]<IntPtr, ulong, ulong, double, ulong, void>)callbacks.OnProgress;
        callback(callbacks.User, tried, total, rate, etaSec);
    }

    private static unsafe void InvokeHit(AcxCallbacks callbacks, byte[] bytes)
    {
        var memory = Marshal.AllocHGlobal(bytes.Length);
        try
        {
            Marshal.Copy(bytes, 0, memory, bytes.Length);
            var callback = (delegate* unmanaged[Cdecl]<IntPtr, IntPtr, nuint, void>)callbacks.OnHit;
            callback(callbacks.User, memory, (nuint)bytes.Length);
        }
        finally
        {
            Marshal.FreeHGlobal(memory);
        }
    }

    private static unsafe void InvokeLog(AcxCallbacks callbacks, int level, string message)
    {
        var memory = Marshal.StringToCoTaskMemUTF8(message);
        try
        {
            var callback = (delegate* unmanaged[Cdecl]<IntPtr, int, IntPtr, void>)callbacks.OnLog;
            callback(callbacks.User, level, memory);
        }
        finally
        {
            Marshal.FreeCoTaskMem(memory);
        }
    }

    private static unsafe void InvokeFinished(AcxCallbacks callbacks, int status)
    {
        var callback = (delegate* unmanaged[Cdecl]<IntPtr, int, void>)callbacks.OnFinished;
        callback(callbacks.User, status);
    }

    private sealed class RecordingSink : INativeCallbackSink
    {
        public int Progress;
        public string? Hit;
        public string? Log;
        public int Finished = -1;

        public void OnProgress(ulong tried, ulong total, double rate, ulong etaSec) => Progress++;

        public void OnHit(byte[] password) => Hit = Convert.ToHexString(password);

        public void OnLog(int level, string message) => Log = $"[{level}] {message}";

        public void OnFinished(int status) => Finished = status;
    }
}
