// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

using ArchCracker.Desktop.Models;
using ArchCracker.Desktop.Native;
using ArchCracker.Desktop.Services;
using ArchCracker.Desktop.ViewModels;
using ArchCracker.Shared;

namespace ArchCracker.Desktop.Tests;

public sealed class WizardViewModelTests
{
    [Fact]
    public void SetupInspectionEnablesStartOnlyForSupportedZip()
    {
        var fixture = new TestFixture();
        var vm = fixture.CreateViewModel();
        fixture.Kernel.Inspection = SupportedInspection();

        vm.ArchivePath = fixture.ArchivePath;
        vm.DictionaryPath = fixture.DictionaryPath;
        ((RelayCommand)vm.InspectArchiveCommand).Execute(null);

        Assert.True(vm.CanStart);
        Assert.False(string.IsNullOrWhiteSpace(vm.ArchiveInfoText));
        Assert.Equal(0, vm.StageIndex);
    }

    [Fact]
    public void UnsupportedInspectionBlocksStart()
    {
        var fixture = new TestFixture();
        var vm = fixture.CreateViewModel();
        fixture.Kernel.Inspection = new ArchiveInspectionResult(
            false,
            AcxStatusKind.Unsupported,
            AcxInspectionInfo.Create(),
            "unencrypted");

        vm.ArchivePath = fixture.ArchivePath;
        vm.DictionaryPath = fixture.DictionaryPath;
        ((RelayCommand)vm.InspectArchiveCommand).Execute(null);

        Assert.False(vm.CanStart);
        Assert.True(vm.HasSetupError);
        Assert.Contains("status.unsupported", vm.SetupErrorText);
    }

    [Fact]
    public void StartAndHitMoveToFoundResult()
    {
        var fixture = new TestFixture();
        var vm = fixture.CreateViewModel();
        fixture.Kernel.Inspection = SupportedInspection();
        vm.ArchivePath = fixture.ArchivePath;
        vm.DictionaryPath = fixture.DictionaryPath;
        ((RelayCommand)vm.InspectArchiveCommand).Execute(null);

        ((RelayCommand)vm.StartCommand).Execute(null);
        fixture.Router.OnProgress(1, 2, 10.0, 1);
        fixture.Router.OnHit("ok"u8.ToArray());
        fixture.Kernel.Status = new JobStatusSnapshot(
            AcxRunStateKind.Finished, 2, 2, 10.0, 0, AcxStatusKind.Ok);
        fixture.Router.OnFinished(0);

        Assert.Equal(1, fixture.Kernel.StartCalls);
        Assert.Equal(2, vm.StageIndex);
        Assert.Equal(JobOutcomeKind.Found, vm.Outcome);
        Assert.Equal("ok", vm.PasswordText);
        Assert.True(vm.HasPassword);
    }

    [Fact]
    public void FinishedWithoutHitIsNotFound()
    {
        var fixture = new TestFixture();
        var vm = fixture.CreateViewModel();
        PrepareStarted(vm, fixture);
        fixture.Kernel.Status = new JobStatusSnapshot(
            AcxRunStateKind.Finished, 2, 2, 10.0, 0, AcxStatusKind.Ok);

        fixture.Router.OnFinished(0);

        Assert.Equal(JobOutcomeKind.NotFound, vm.Outcome);
        Assert.False(vm.HasPassword);
        Assert.Equal(2, vm.StageIndex);
    }

    [Fact]
    public void NonUtf8PasswordFallsBackToHex()
    {
        var fixture = new TestFixture();
        var vm = fixture.CreateViewModel();
        PrepareStarted(vm, fixture);

        fixture.Router.OnHit(new byte[] { 0xff, 0xfe });

        Assert.Equal("FFFE", vm.PasswordText);
        Assert.Equal("FFFE", vm.PasswordHex);
    }

    [Fact]
    public void PauseResumeAndStopChangeRunState()
    {
        var fixture = new TestFixture();
        var vm = fixture.CreateViewModel();
        PrepareStarted(vm, fixture);

        ((RelayCommand)vm.PauseCommand).Execute(null);
        Assert.Equal(AcxRunStateKind.Paused, fixture.Kernel.Status.State);
        Assert.True(vm.CanResume);

        ((RelayCommand)vm.ResumeCommand).Execute(null);
        Assert.Equal(AcxRunStateKind.Running, fixture.Kernel.Status.State);
        Assert.True(vm.CanStop);

        ((RelayCommand)vm.StopCommand).Execute(null);
        Assert.Equal(1, fixture.Kernel.StopCalls);
        Assert.Equal(AcxRunStateKind.Stopped, fixture.Kernel.Status.State);
    }

    [Fact]
    public void SelectingSetupAfterResultResetsAndAllowsAnotherRun()
    {
        var fixture = new TestFixture();
        var vm = fixture.CreateViewModel();
        PrepareStarted(vm, fixture);
        fixture.Kernel.Status = new JobStatusSnapshot(
            AcxRunStateKind.Finished, 2, 2, 10.0, 0, AcxStatusKind.Ok);
        fixture.Router.OnHit("ok"u8.ToArray());
        fixture.Router.OnFinished(0);

        vm.StageIndex = 0;

        Assert.Equal(0, vm.StageIndex);
        Assert.Equal(JobOutcomeKind.Pending, vm.Outcome);
        Assert.False(vm.HasPassword);
        Assert.True(vm.CanStart);
        Assert.Equal(1, fixture.Kernel.StartCalls);

        ((RelayCommand)vm.StartCommand).Execute(null);
        Assert.Equal(2, fixture.Kernel.StartCalls);
        Assert.Equal(1, vm.StageIndex);
    }

    [Fact]
    public void SetupTabIsDisabledDuringRunAndEnabledAfterTerminal()
    {
        var fixture = new TestFixture();
        var vm = fixture.CreateViewModel();
        PrepareStarted(vm, fixture);
        Assert.False(vm.CanOpenSetup);

        fixture.Kernel.Status = new JobStatusSnapshot(
            AcxRunStateKind.Stopped, 1, 2, 10.0, 0, AcxStatusKind.Ok);
        fixture.Router.OnFinished(0);

        Assert.True(vm.CanOpenSetup);
    }

    [Fact]
    public void ResetClearsResultAndReturnsToSetup()
    {
        var fixture = new TestFixture();
        var vm = fixture.CreateViewModel();
        PrepareStarted(vm, fixture);
        fixture.Kernel.Status = new JobStatusSnapshot(
            AcxRunStateKind.Finished, 2, 2, 10.0, 0, AcxStatusKind.Ok);
        fixture.Router.OnHit("ok"u8.ToArray());
        fixture.Router.OnFinished(0);

        ((RelayCommand)vm.ResetCommand).Execute(null);

        Assert.Equal(0, vm.StageIndex);
        Assert.Equal(JobOutcomeKind.Pending, vm.Outcome);
        Assert.False(vm.HasPassword);
    }

    [Fact]
    public void FinishedWithNonOkStatusIsFailed()
    {
        var fixture = new TestFixture();
        var vm = fixture.CreateViewModel();
        PrepareStarted(vm, fixture);
        fixture.Kernel.Status = new JobStatusSnapshot(
            AcxRunStateKind.Finished, 2, 2, 10.0, 0, AcxStatusKind.Archive);
        fixture.Router.OnHit("ok"u8.ToArray());

        fixture.Router.OnFinished(4);

        Assert.Equal(JobOutcomeKind.Failed, vm.Outcome);
        Assert.Equal(2, vm.StageIndex);
    }

    [Fact]
    public void TerminalIsLockedAfterRuntimeError()
    {
        var fixture = new TestFixture();
        var vm = fixture.CreateViewModel();
        PrepareStarted(vm, fixture);
        fixture.Kernel.ThrowOnPause = true;

        ((RelayCommand)vm.PauseCommand).Execute(null);
        fixture.Router.OnFinished(0);

        Assert.Equal(JobOutcomeKind.Failed, vm.Outcome);
        Assert.Contains("pause failed", vm.ResultText);
    }

    [Fact]
    public void StoppedTerminalOutcomeIsStopped()
    {
        var fixture = new TestFixture();
        var vm = fixture.CreateViewModel();
        PrepareStarted(vm, fixture);
        ((RelayCommand)vm.StopCommand).Execute(null);

        fixture.Router.OnFinished(0);

        Assert.Equal(JobOutcomeKind.Stopped, vm.Outcome);
        Assert.Equal(2, vm.StageIndex);
    }

    [Fact]
    public void RouterResetClearsStaleProgress()
    {
        var router = new NativeCallbackRouter(new ImmediateUiDispatcher());
        var progress = new List<ProgressSnapshot>();
        router.Progress += progress.Add;
        router.OnProgress(1, 2, 1.0, 1);
        router.Reset();
        router.OnFinished(0);

        Assert.Single(progress);
    }

    [Fact]
    public void ClipboardFailureDoesNotClaimSuccess()
    {
        var fixture = new TestFixture();
        fixture.Shell.Succeeds = false;
        var vm = fixture.CreateViewModel();
        PrepareStarted(vm, fixture);
        fixture.Router.OnHit("ok"u8.ToArray());

        ((AsyncRelayCommand)vm.CopyPasswordCommand).Execute(null);

        Assert.Null(fixture.Shell.CopiedText);
        Assert.Contains(vm.Log, entry => entry.Contains("log.copy_failed", StringComparison.Ordinal));
    }

    [Fact]
    public void CopyAndOpenFolderUseShellService()
    {
        var fixture = new TestFixture();
        var vm = fixture.CreateViewModel();
        PrepareStarted(vm, fixture);
        fixture.Router.OnHit("copy-me"u8.ToArray());

        ((AsyncRelayCommand)vm.CopyPasswordCommand).Execute(null);
        ((RelayCommand)vm.OpenFolderCommand).Execute(null);

        Assert.Equal("copy-me", fixture.Shell.CopiedText);
        Assert.Equal(fixture.ArchivePath, fixture.Shell.OpenedPath);
    }

    private static void PrepareStarted(MainWindowViewModel vm, TestFixture fixture)
    {
        fixture.Kernel.Inspection = SupportedInspection();
        vm.ArchivePath = fixture.ArchivePath;
        vm.DictionaryPath = fixture.DictionaryPath;
        ((RelayCommand)vm.InspectArchiveCommand).Execute(null);
        ((RelayCommand)vm.StartCommand).Execute(null);
    }

    private static ArchiveInspectionResult SupportedInspection()
{
    var info = AcxInspectionInfo.Create();
    info.Format = AcxFormatCode.Zip;
    info.Encryption = AcxEncryptionCode.ZipCrypto;
    info.EntryCount = 1;
    info.SelectedIndex = 0;
    info.HasVerificationTarget = 1;
    return new ArchiveInspectionResult(true, AcxStatusKind.Ok, info, string.Empty);
}

private sealed class TestFixture : IDisposable
    {
        public TestFixture()
        {
            var name = $"acx-wizard-{Guid.NewGuid():N}";
            var preferred = Path.Combine(Path.GetTempPath(), name);
            try
            {
                System.IO.Directory.CreateDirectory(preferred);
                Directory = preferred;
            }
            catch (UnauthorizedAccessException)
            {
                Directory = Path.Combine(AppContext.BaseDirectory, name);
                System.IO.Directory.CreateDirectory(Directory);
            }

            ArchivePath = Path.Combine(Directory, "fixture.zip");
            DictionaryPath = Path.Combine(Directory, "dict.txt");
            ArchCracker.Shared.Testing.ZipCryptoFixture.Write(
                ArchivePath, "ok", "hello.txt", "hello");
            File.WriteAllText(DictionaryPath, "wrong\nok\n");
            Router = new NativeCallbackRouter(new ImmediateUiDispatcher());
        }

        public string Directory { get; }
        public string ArchivePath { get; }
        public string DictionaryPath { get; }
        public FakeKernelService Kernel { get; } = new();
        public NativeCallbackRouter Router { get; }
        public FakeShellService Shell { get; } = new();

        public MainWindowViewModel CreateViewModel() => new(
            Kernel,
            new FakeLocalizationService(),
            new FakeThemeService(),
            Router,
            new FakeCallbackProvider(),
            new FakeFilePickerService(),
            Shell);

        public void Dispose()
        {
            try { System.IO.Directory.Delete(Directory, true); }
            catch (IOException) { }
        }
    }
}
