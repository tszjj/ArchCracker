// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

using System.Diagnostics;
using ArchCracker.Desktop.Services;

namespace ArchCracker.Desktop.Tests;

public sealed class CallbackThrottleTests
{
    [Fact]
    public void ThrottleEmitsFirstThenSuppressesUntilIntervalElapsed()
    {
        var now = 0L;
        var interval = (long)(Stopwatch.Frequency * 0.1);
        var throttle = new ProgressThrottle(100, () => now);

        Assert.True(throttle.ShouldEmit());
        now += interval - 1;
        Assert.False(throttle.ShouldEmit());
        now += 2;
        Assert.True(throttle.ShouldEmit());
    }

    [Fact]
    public void RouterDeliversCallbackDataOnDispatcher()
    {
        var dispatcher = new ImmediateUiDispatcher();
        var router = new NativeCallbackRouter(dispatcher);
        var progress = new List<ProgressSnapshot>();
        var hits = new List<string>();
        var logs = new List<string>();
        var finished = new List<int>();

        router.Progress += progress.Add;
        router.Hit += hits.Add;
        router.Log += logs.Add;
        router.Finished += finished.Add;

        router.OnProgress(1, 2, 3.0, 4);
        router.OnHit(new byte[] { 0x41, 0x42 });
        router.OnLog(2, "message");
        router.OnFinished(0);

        Assert.Equal(2, progress.Count); // live update + final snapshot on finish
        Assert.Equal(1ul, progress[0].Tried);
        Assert.Equal(1ul, progress[1].Tried);
        Assert.Equal("4142", Assert.Single(hits));
        Assert.Equal("[2] message", Assert.Single(logs));
        Assert.Equal(0, Assert.Single(finished));
    }

    private sealed class ImmediateUiDispatcher : IUiDispatcher
    {
        public void Post(Action action) => action();
    }
}
