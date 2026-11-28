// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

using ArchCracker.Desktop.Native;

namespace ArchCracker.Desktop.Services;

public sealed record ProgressSnapshot(ulong Tried, ulong Total, double Rate, ulong EtaSec);

/// <summary>
/// Converts native callbacks into UI-thread-delivered events and limits
/// progress updates to approximately 10 Hz. It deliberately has no NativeBridge
/// or Avalonia control dependencies.
/// </summary>
public sealed class NativeCallbackRouter : INativeCallbackSink
{
    private readonly IUiDispatcher _dispatcher;
    private readonly ProgressThrottle _progressThrottle = new(100);
    private ProgressSnapshot? _lastProgress;

    public NativeCallbackRouter(IUiDispatcher dispatcher) => _dispatcher = dispatcher;

    public void Reset()
    {
        _lastProgress = null;
        _progressThrottle.Reset();
    }

    public event Action<ProgressSnapshot>? Progress;
    public event Action<string>? Hit;
    public event Action<byte[]>? HitBytes;
    public event Action<string>? Log;
    public event Action<int>? Finished;

    public void OnProgress(ulong tried, ulong total, double rate, ulong etaSec)
    {
        var snapshot = new ProgressSnapshot(tried, total, rate, etaSec);
        _lastProgress = snapshot;
        if (!_progressThrottle.ShouldEmit()) return;
        _dispatcher.Post(() => Progress?.Invoke(snapshot));
    }

    public void OnHit(byte[] password)
    {
        var copy = password.ToArray();
        var full = Convert.ToHexString(copy);
        var display = full.Length <= 16 ? full : $"{full[..16]}…";
        _dispatcher.Post(() =>
        {
            Hit?.Invoke(display);
            HitBytes?.Invoke(copy);
        });
    }

    public void OnLog(int level, string message) =>
        _dispatcher.Post(() => Log?.Invoke($"[{level}] {message}"));

    public void OnFinished(int status)
    {
        var final = _lastProgress;
        _dispatcher.Post(() =>
        {
            if (final is not null) Progress?.Invoke(final);
            Finished?.Invoke(status);
        });
    }
}
