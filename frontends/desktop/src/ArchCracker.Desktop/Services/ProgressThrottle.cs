// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

using System.Diagnostics;

namespace ArchCracker.Desktop.Services;

public sealed class ProgressThrottle
{
    private readonly long _intervalUnits;
    private readonly Func<long> _clock;
    private long _lastTicks = long.MinValue;

    public ProgressThrottle(int intervalMs = 100, Func<long>? clock = null)
    {
        _intervalUnits = (long)(Stopwatch.Frequency * (Math.Max(1, intervalMs) / 1000.0));
        _clock = clock ?? Stopwatch.GetTimestamp;
    }

    public void Reset() => Interlocked.Exchange(ref _lastTicks, long.MinValue);

    public bool ShouldEmit()
    {
        var now = _clock();
        var previous = Interlocked.Read(ref _lastTicks);
        if (previous != long.MinValue && now - previous < _intervalUnits) return false;
        return Interlocked.CompareExchange(ref _lastTicks, now, previous) == previous;
    }
}
