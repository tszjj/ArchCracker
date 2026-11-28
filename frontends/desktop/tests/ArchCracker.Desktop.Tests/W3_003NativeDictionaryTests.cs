// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

using System.Diagnostics;
using System.Windows.Input;
using ArchCracker.Desktop.Models;
using ArchCracker.Desktop.Native;
using ArchCracker.Desktop.Services;
using ArchCracker.Desktop.ViewModels;
using ArchCracker.Shared.Testing;

namespace ArchCracker.Desktop.Tests;

public sealed class W3_003NativeDictionaryTests
{
    private const string Password = "ok";

    [Fact]
    public void WizardAndCliAgreeOnFound()
    {
        var root = CreateTempDirectory();
        try
        {
            var archive = Path.Combine(root, "found.zip");
            var dictionary = Path.Combine(root, "found.txt");
            ZipCryptoFixture.Write(archive, Password, "hello.txt", "hello");
            File.WriteAllText(dictionary, "wrong\nok\n");

            using var wizard = RunWizard(archive, dictionary);
            AssertFound(wizard, wizard.Dispatcher, wizard.Probe);
            Assert.Equal(0, RunCli(archive, dictionary));
        }
        finally { Cleanup(root); }
    }

    [Fact]
    public void WizardAndCliAgreeOnNotFound()
    {
        var root = CreateTempDirectory();
        try
        {
            var archive = Path.Combine(root, "miss.zip");
            var dictionary = Path.Combine(root, "miss.txt");
            ZipCryptoFixture.Write(archive, Password, "hello.txt", "hello");
            File.WriteAllText(dictionary, "wrong\nother\n");

            using var wizard = RunWizard(archive, dictionary);
            Assert.Equal(JobOutcomeKind.NotFound, WaitForOutcome(wizard.ViewModel, wizard.Dispatcher, wizard.Probe));
            Assert.False(wizard.ViewModel.HasPassword);
            Assert.Equal(1, RunCli(archive, dictionary));
        }
        finally { Cleanup(root); }
    }

    [Fact]
    public void WizardAndCliAgreeOnUnencryptedArchiveError()
    {
        var root = CreateTempDirectory();
        try
        {
            var archive = Path.Combine(root, "plain.zip");
            var dictionary = Path.Combine(root, "error.txt");
            ZipCryptoFixture.WritePlain(archive, "hello.txt", "hello");
            File.WriteAllText(dictionary, "ok\n");

            using var wizard = CreateWizard();
            var vm = wizard.ViewModel;
            vm.ArchivePath = archive;
            vm.DictionaryPath = dictionary;
            ((ICommand)vm.InspectArchiveCommand).Execute(null);

            Assert.False(vm.CanStart);
            Assert.True(vm.HasSetupError);
            Assert.Contains("status.unsupported", vm.SetupErrorText);
            Assert.Equal(3, RunCli(archive, dictionary));
        }
        finally { Cleanup(root); }
    }

    private static void AssertFound(WizardHarness wizard, QueuedUiDispatcher dispatcher, CallbackProbe probe)
    {
        var vm = wizard.ViewModel;
        var outcome = WaitForOutcome(vm, dispatcher, probe);
        Assert.Equal(JobOutcomeKind.Found, outcome);
        Assert.Equal(Password, vm.PasswordText);
        Assert.Equal(2, vm.StageIndex);
    }

    private static JobOutcomeKind WaitForOutcome(
        MainWindowViewModel vm,
        QueuedUiDispatcher dispatcher,
        CallbackProbe probe)
    {
        Assert.True(probe.Finished.Wait(TimeSpan.FromSeconds(20)), "GUI attack timed out");
        dispatcher.Drain();
        return vm.Outcome;
    }

    private static WizardHarness RunWizard(string archive, string dictionary)
    {
        var wizard = CreateWizard();
        var vm = wizard.ViewModel;
        vm.ArchivePath = archive;
        vm.DictionaryPath = dictionary;
        ((ICommand)vm.InspectArchiveCommand).Execute(null);
        Assert.True(vm.CanStart);
        ((ICommand)vm.StartCommand).Execute(null);
        return wizard;
    }

    private static WizardHarness CreateWizard()
    {
        var kernel = new KernelService();
        var dispatcher = new QueuedUiDispatcher();
        var router = new NativeCallbackRouter(dispatcher);
        var probe = new CallbackProbe(router);
        var bridge = new AcxCallbackBridge(probe);
        var vm = new MainWindowViewModel(
            kernel,
            new FakeLocalizationService(),
            new FakeThemeService(),
            router,
            bridge,
            new FakeFilePickerService(),
            new FakeShellService());
        return new WizardHarness(vm, bridge, dispatcher, probe);
    }

    private static int RunCli(string archive, string dictionary)
    {
        var executable = FindRepoFile("core", "target", "debug", "acx.exe");
        Assert.True(executable is not null, "core/target/debug/acx.exe is required for GUI↔CLI differential");

        var start = new ProcessStartInfo
        {
            FileName = executable!,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        start.ArgumentList.Add("-f");
        start.ArgumentList.Add(archive);
        start.ArgumentList.Add("-d");
        start.ArgumentList.Add(dictionary);
        start.ArgumentList.Add("-t");
        start.ArgumentList.Add("1");

        using var process = Process.Start(start)!;
        process.StandardOutput.ReadToEnd();
        process.StandardError.ReadToEnd();
        Assert.True(process.WaitForExit(20_000), "CLI attack timed out");
        return process.ExitCode;
    }

    private static string? FindRepoFile(params string[] parts)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            var candidate = Path.Combine(directory.FullName, Path.Combine(parts));
            if (File.Exists(candidate)) return candidate;
            directory = directory.Parent;
        }
        return null;
    }

    private static string CreateTempDirectory()
    {
        var name = $"acx-w3-003-{Guid.NewGuid():N}";
        var preferred = Path.Combine(Path.GetTempPath(), name);
        try
        {
            Directory.CreateDirectory(preferred);
            return preferred;
        }
        catch (UnauthorizedAccessException)
        {
            var fallback = Path.Combine(AppContext.BaseDirectory, name);
            Directory.CreateDirectory(fallback);
            return fallback;
        }
    }

    private static void Cleanup(string root)
    {
        try { Directory.Delete(root, true); }
        catch (IOException) { }
    }

    private sealed class WizardHarness : IDisposable
    {
        public WizardHarness(
            MainWindowViewModel viewModel,
            AcxCallbackBridge bridge,
            QueuedUiDispatcher dispatcher,
            CallbackProbe probe)
        {
            ViewModel = viewModel;
            Bridge = bridge;
            Dispatcher = dispatcher;
            Probe = probe;
        }

        public MainWindowViewModel ViewModel { get; }
        public AcxCallbackBridge Bridge { get; }
        public QueuedUiDispatcher Dispatcher { get; }
        public CallbackProbe Probe { get; }

        public void Dispose()
        {
            ViewModel.Dispose();
            Bridge.Dispose();
            Probe.Finished.Dispose();
        }
    }

    private sealed class QueuedUiDispatcher : IUiDispatcher
    {
        private readonly System.Collections.Concurrent.ConcurrentQueue<Action> _queue = new();

        public void Post(Action action) => _queue.Enqueue(action);

        public void Drain()
        {
            while (_queue.TryDequeue(out var action)) action();
        }
    }

    private sealed class CallbackProbe : INativeCallbackSink
    {
        private readonly NativeCallbackRouter _router;

        public CallbackProbe(NativeCallbackRouter router) => _router = router;

        public ManualResetEventSlim Finished { get; } = new(false);

        public void OnProgress(ulong tried, ulong total, double rate, ulong etaSec) =>
            _router.OnProgress(tried, total, rate, etaSec);

        public void OnHit(byte[] password) => _router.OnHit(password);

        public void OnLog(int level, string message) => _router.OnLog(level, message);

        public void OnFinished(int status)
        {
            _router.OnFinished(status);
            Finished.Set();
        }
    }
}
