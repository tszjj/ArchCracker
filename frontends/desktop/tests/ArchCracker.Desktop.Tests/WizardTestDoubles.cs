// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

using ArchCracker.Desktop.Models;
using ArchCracker.Desktop.Native;
using ArchCracker.Desktop.Services;
using ArchCracker.Shared;

namespace ArchCracker.Desktop.Tests;

internal sealed class FakeKernelService : IKernelService
{
    public ArchiveInspectionResult Inspection { get; set; } = new(
        true,
        AcxStatusKind.Ok,
        AcxInspectionInfo.Create(),
        string.Empty);

    public JobStatusSnapshot Status { get; set; } = new(
        AcxRunStateKind.Idle, 0, 0, 0, 0, AcxStatusKind.Ok);

    public int StartCalls { get; private set; }
    public int PauseCalls { get; private set; }
    public int ResumeCalls { get; private set; }
    public int StopCalls { get; private set; }
    public bool ThrowOnStart { get; set; }
    public bool ThrowOnPause { get; set; }
    public bool ThrowOnResume { get; set; }
    public bool ThrowOnStop { get; set; }

    public string LibraryPath => "fake-acx.dll";

    public KernelProbeResult Probe() => new(
        true, "ArchCracker", "test", 1, LibraryPath, AcxStatusKind.Ok, string.Empty,
        AcxLibraryIntegrity.NotPinned);

    public ArchiveInspectionResult Inspect(string path) => Inspection;

    public AcxJobHandle CreateHandle() => AcxJobHandle.CreateTestHandle();

    public void DestroyHandle(AcxJobHandle handle) => handle.Dispose();

    public JobStatusSnapshot GetStatus(AcxJobHandle handle) => Status;

    public AcxStatusKind Start(AcxJobHandle handle, in AcxAttackSpec spec, in AcxCallbacks callbacks)
    {
        StartCalls++;
        if (ThrowOnStart) throw new InvalidOperationException("start failed");
        Status = Status with { State = AcxRunStateKind.Running };
        return AcxStatusKind.Ok;
    }

    public AcxStatusKind Pause(AcxJobHandle handle)
    {
        PauseCalls++;
        if (ThrowOnPause) throw new InvalidOperationException("pause failed");
        Status = Status with { State = AcxRunStateKind.Paused };
        return AcxStatusKind.Ok;
    }

    public AcxStatusKind Resume(AcxJobHandle handle)
    {
        ResumeCalls++;
        Status = Status with { State = AcxRunStateKind.Running };
        return AcxStatusKind.Ok;
    }

    public AcxStatusKind Stop(AcxJobHandle handle)
    {
        StopCalls++;
        Status = Status with { State = AcxRunStateKind.Stopped };
        return AcxStatusKind.Ok;
    }

    public AcxEstimateInfo Estimate(in AcxAttackSpec spec) => AcxEstimateInfo.Create();
}

internal sealed class FakeCallbackProvider : INativeCallbackProvider
{
    public unsafe AcxCallbacks Callbacks { get; } = new()
    {
        StructSize = (uint)sizeof(AcxCallbacks),
        Version = 1,
    };
}

internal sealed class FakeFilePickerService : IFilePickerService
{
    public string? ArchiveResult { get; set; }
    public string? DictionaryResult { get; set; }

    public Task<string?> PickArchiveAsync() => Task.FromResult(ArchiveResult);

    public Task<string?> PickDictionaryAsync() => Task.FromResult(DictionaryResult);
}

internal sealed class FakeShellService : IShellService
{
    public string? CopiedText { get; private set; }
    public string? OpenedPath { get; private set; }

    public void OpenContainingFolder(string path) => OpenedPath = path;

    public bool Succeeds { get; set; } = true;

    public Task<bool> CopyToClipboardAsync(string text)
    {
        if (Succeeds) CopiedText = text;
        return Task.FromResult(Succeeds);
    }
}

internal sealed class FakeLocalizationService : ILocalizationService
{
    public string Language => "en";
    public IReadOnlyList<string> Languages => new[] { "en" };
    public string this[string key] => key;
    public event EventHandler? LanguageChanged;

    public void SetLanguage(string language) => LanguageChanged?.Invoke(this, EventArgs.Empty);
}

internal sealed class FakeThemeService : IThemeService
{
    public ThemeKind Current { get; private set; } = ThemeKind.Dark;
    public event EventHandler? ThemeChanged;

    public void Set(ThemeKind theme)
    {
        Current = theme;
        ThemeChanged?.Invoke(this, EventArgs.Empty);
    }
}

internal sealed class ImmediateUiDispatcher : IUiDispatcher
{
    public void Post(Action action) => action();
}
