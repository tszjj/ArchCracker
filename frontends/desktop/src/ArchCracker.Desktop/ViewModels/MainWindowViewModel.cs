// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

using System.Collections.ObjectModel;
using System.Text;
using System.Windows.Input;
using ArchCracker.Desktop.Models;
using ArchCracker.Desktop.Native;
using ArchCracker.Desktop.Services;
using ArchCracker.Shared;

namespace ArchCracker.Desktop.ViewModels;

public sealed class MainWindowViewModel : ObservableObject, IDisposable
{
    private readonly IKernelService _kernel;
    private readonly ILocalizationService _localization;
    private readonly IThemeService _theme;
    private readonly NativeCallbackRouter _callbacks;
    private readonly INativeCallbackProvider _callbackProvider;
    private readonly IFilePickerService _filePicker;
    private readonly IShellService _shell;
    private readonly SidecarOptions _sidecar;
    private AcxJobHandle? _handle;
    private TempCheckpoint? _checkpoint;
    private KernelProbeResult _probe = new(false, string.Empty, string.Empty, 0, string.Empty,
        AcxStatusKind.Internal, string.Empty, AcxLibraryIntegrity.NotPinned);
    private string _archivePath = string.Empty;
    private string _dictionaryPath = string.Empty;
    private ArchiveInspectionResult? _inspection;
    private string _setupError = string.Empty;
    private string _archiveInfo = string.Empty;
    private int _threads;
    private int _stageIndex;
    private AcxRunStateKind _runState = AcxRunStateKind.Idle;
    private JobOutcomeKind _outcome = JobOutcomeKind.Pending;
    private bool _terminalLocked;
    private string _progressText = string.Empty;
    private string _resultText = string.Empty;
    private ProgressSnapshot? _progress;
    private byte[]? _passwordBytes;
    private string _statusText = string.Empty;

    public MainWindowViewModel(
        IKernelService kernel,
        ILocalizationService localization,
        IThemeService theme,
        NativeCallbackRouter callbacks,
        INativeCallbackProvider callbackProvider,
        IFilePickerService filePicker,
        IShellService shell,
        SidecarOptions? sidecar = null)
    {
        _kernel = kernel;
        _localization = localization;
        _theme = theme;
        _callbacks = callbacks;
        _callbackProvider = callbackProvider;
        _filePicker = filePicker;
        _shell = shell;
        _sidecar = sidecar ?? new SidecarOptions(false);
        _threads = Math.Max(1, Math.Min(Environment.ProcessorCount, 8));

        _callbacks.Progress += OnProgress;
        _callbacks.HitBytes += OnHit;
        _callbacks.Log += OnLog;
        _callbacks.Finished += OnFinished;
        _localization.LanguageChanged += OnLocalizationChanged;
        _theme.ThemeChanged += OnThemeChanged;

        BrowseArchiveCommand = new AsyncRelayCommand(BrowseArchiveAsync);
        BrowseDictionaryCommand = new AsyncRelayCommand(BrowseDictionaryAsync);
        InspectArchiveCommand = new RelayCommand(InspectArchive, () => CanInspect);
        StartCommand = new RelayCommand(Start, () => CanStart);
        PauseCommand = new RelayCommand(Pause, () => CanPause);
        ResumeCommand = new RelayCommand(Resume, () => CanResume);
        StopCommand = new RelayCommand(Stop, () => CanStop);
        CopyPasswordCommand = new AsyncRelayCommand(CopyPasswordAsync, () => _passwordBytes is not null);
        OpenFolderCommand = new RelayCommand(OpenFolder, () => !string.IsNullOrWhiteSpace(_archivePath));
        ResetCommand = new RelayCommand(Reset);
        RefreshCommand = new RelayCommand(Refresh);
        ToggleThemeCommand = new RelayCommand(ToggleTheme);
        ToggleLanguageCommand = new RelayCommand(ToggleLanguage);
        Refresh();
    }

    public ICommand BrowseArchiveCommand { get; }
    public ICommand BrowseDictionaryCommand { get; }
    public ICommand InspectArchiveCommand { get; }
    public ICommand StartCommand { get; }
    public ICommand PauseCommand { get; }
    public ICommand ResumeCommand { get; }
    public ICommand StopCommand { get; }
    public ICommand CopyPasswordCommand { get; }
    public ICommand OpenFolderCommand { get; }
    public ICommand ResetCommand { get; }
    public ICommand RefreshCommand { get; }
    public ICommand ToggleThemeCommand { get; }
    public ICommand ToggleLanguageCommand { get; }

    public ObservableCollection<string> Log { get; } = new();

    public string TitleText => _localization["app.title"];
    public string SubtitleText => _localization["app.subtitle"];
    public string ProductLabel => _localization["view.product"];
    public string VersionLabel => _localization["view.version"];
    public string AbiLibraryLabel => _localization["view.abi_library"];
    public string ProductText => _probe.Product;
    public string VersionText => _probe.Version;
    public string AbiText => _probe.AbiVersion.ToString();
    public string LibraryPathText => _kernel.LibraryPath;
    public string KernelStatusText => _localization[_probe.Available ? "kernel.available" : "kernel.unavailable"];
    public string ErrorText => _probe.Error;
    public bool HasError => !string.IsNullOrWhiteSpace(_probe.Error);
    public string IntegrityText => $"{_localization["kernel.library"]}: {_probe.Integrity}";
    public string SidecarText => $"{_localization["view.sidecar"]}: {(_sidecar.Enabled ? "on" : "off")} (P2)";

    public int StageIndex
    {
        get => _stageIndex;
        set
        {
            var next = Math.Clamp(value, 0, 2);
            if (_stageIndex == next) return;
            _stageIndex = next;
            RaisePropertyChanged();
            RaisePropertyChanged(nameof(IsRunStage));
            RaisePropertyChanged(nameof(IsResultStage));
        }
    }

    public string ArchivePath
    {
        get => _archivePath;
        set
        {
            _archivePath = value ?? string.Empty;
            _inspection = null;
            _archiveInfo = string.Empty;
            _setupError = string.Empty;
            RaisePropertyChanged();
            RaisePropertyChanged(nameof(CanStart));
            RaisePropertyChanged(nameof(ArchiveInfoText));
            RaisePropertyChanged(nameof(SetupErrorText));
            RaisePropertyChanged(nameof(HasSetupError));
            RefreshCommands();
        }
    }

    public string DictionaryPath
    {
        get => _dictionaryPath;
        set
        {
            _dictionaryPath = value ?? string.Empty;
            RaisePropertyChanged();
            RaisePropertyChanged(nameof(CanStart));
            RefreshCommands();
        }
    }

    public int Threads
    {
        get => _threads;
        set
        {
            _threads = Math.Max(1, Math.Min(value, Environment.ProcessorCount));
            RaisePropertyChanged();
        }
    }

    public int MaxThreads => Environment.ProcessorCount;
    public IReadOnlyList<int> ThreadOptions => Enumerable.Range(1, MaxThreads).ToArray();
    public bool IsRunStage => _stageIndex == 1;
    public bool IsResultStage => _stageIndex == 2;
    public double ProgressPercent => _progress is null || _progress.Total == 0
        ? 0
        : Math.Clamp(100.0 * _progress.Tried / _progress.Total, 0, 100);
    public string ArchiveInfoText => _archiveInfo;
    public string SetupErrorText => _setupError;
    public bool HasSetupError => !string.IsNullOrWhiteSpace(_setupError);
    public string RunStateText => $"{_localization["view.state"]}: {_runState}";
    public string ProgressText => _progressText;
    public string ResultText => _resultText;
    public string PasswordText => _passwordBytes is null
        ? string.Empty
        : SafePasswordText(_passwordBytes);
    public string PasswordHex => _passwordBytes is null
        ? string.Empty
        : Convert.ToHexString(_passwordBytes);
    public bool HasPassword => _passwordBytes is not null;
    public JobOutcomeKind Outcome => _outcome;

    public bool CanInspect => _probe.Available && !string.IsNullOrWhiteSpace(_archivePath) && _handle is null;
    public bool CanStart
    {
        get
        {
            if (!_probe.Available || _inspection?.Success != true || _handle is not null
                || _outcome != JobOutcomeKind.Pending || _threads is < 1 or > 256)
                return false;
            if (!File.Exists(_archivePath) || !File.Exists(_dictionaryPath)) return false;
            try { return new FileInfo(_dictionaryPath).Length > 0; }
            catch (IOException) { return false; }
            catch (UnauthorizedAccessException) { return false; }
        }
    }
    public bool CanPause => _runState == AcxRunStateKind.Running && _handle is not null;
    public bool CanResume => _runState == AcxRunStateKind.Paused && _handle is not null;
    public bool CanStop => _handle is not null
        && _runState is AcxRunStateKind.Running or AcxRunStateKind.Paused;

    public string SetupHeader => _localization["view.setup"];
    public string RunHeader => _localization["view.run"];
    public string ResultHeader => _localization["view.result"];
    public string ArchiveLabel => _localization["view.archive"];
    public string DictionaryLabel => _localization["view.dictionary"];
    public string ThreadsLabel => _localization["view.threads"];
    public string BrowseLabel => _localization["view.browse"];
    public string InspectLabel => _localization["view.inspect"];
    public string StartLabel => _localization["view.start"];
    public string PauseLabel => _localization["view.pause"];
    public string ResumeLabel => _localization["view.resume"];
    public string StopLabel => _localization["view.stop"];
    public string CopyPasswordLabel => _localization["view.copy_password"];
    public string OpenFolderLabel => _localization["view.open_folder"];
    public string ResetLabel => _localization["view.reset"];
    public string RefreshLabel => _localization["view.refresh"];
    public string ThemeLabel => $"{_localization["view.toggle_theme"]} ({_theme.Current})";
    public string LanguageLabel => _localization["view.toggle_language"];
    public string LogLabel => _localization["view.log"];

    public void SetArchivePath(string path)
    {
        ArchivePath = path;
        InspectArchive();
    }

    public void Dispose()
    {
        if (_handle is not null && CanStop)
        {
            try { _kernel.Stop(_handle); } catch { /* disposal must not throw */ }
        }
        _handle?.Dispose();
        _handle = null;
        _checkpoint?.Dispose();
        _checkpoint = null;
        _callbacks.Progress -= OnProgress;
        _callbacks.HitBytes -= OnHit;
        _callbacks.Log -= OnLog;
        _callbacks.Finished -= OnFinished;
        _localization.LanguageChanged -= OnLocalizationChanged;
        _theme.ThemeChanged -= OnThemeChanged;
    }

    private async Task BrowseArchiveAsync()
    {
        var path = await _filePicker.PickArchiveAsync();
        if (!string.IsNullOrWhiteSpace(path)) SetArchivePath(path);
    }

    private async Task BrowseDictionaryAsync()
    {
        var path = await _filePicker.PickDictionaryAsync();
        if (!string.IsNullOrWhiteSpace(path)) DictionaryPath = path;
    }

    private void InspectArchive()
    {
        if (!CanInspect) return;
        var result = _kernel.Inspect(_archivePath);
        _inspection = result;
        if (!result.Success)
        {
            _setupError = $"{_localization[AcxStatusMap.Key(result.Status)]}: {result.Error}";
            _archiveInfo = string.Empty;
        }
        else if (result.Info.Format != AcxFormatCode.Zip)
        {
            _setupError = _localization["error.only_zip"];
            _archiveInfo = string.Empty;
            _inspection = result with { Success = false };
        }
        else if (result.Info.Encryption is not (AcxEncryptionCode.ZipCrypto or AcxEncryptionCode.Aes)
                 || result.Info.HasVerificationTarget == 0)
        {
            _setupError = _localization["error.no_target"];
            _archiveInfo = string.Empty;
            _inspection = result with { Success = false };
        }
        else
        {
            _setupError = string.Empty;
            _archiveInfo = string.Format(
                _localization["view.archive_info"],
                result.Info.EntryCount,
                EncryptionName(result.Info.Encryption),
                result.Info.HeaderEncrypted != 0);
        }

        RaisePropertyChanged(nameof(ArchiveInfoText));
        RaisePropertyChanged(nameof(SetupErrorText));
        RaisePropertyChanged(nameof(HasSetupError));
        RaisePropertyChanged(nameof(CanStart));
        RefreshCommands();
    }

    private void Start()
    {
        if (!CanStart) return;
        try
        {
            _callbacks.Reset();
            _checkpoint?.Dispose();
            _checkpoint = TempCheckpoint.Create();
            _handle = _kernel.CreateHandle();
            var spec = AttackSpecFactory.CreateDictionary(
                _archivePath, _dictionaryPath, _checkpoint.Path, (uint)_threads);
            try
            {
                _kernel.Start(_handle, spec, _callbackProvider.Callbacks);
            }
            finally
            {
                AttackSpecFactory.Free(spec);
            }

            _outcome = JobOutcomeKind.Pending;
            _terminalLocked = false;
            _runState = AcxRunStateKind.Running;
            _progressText = string.Empty;
            _progress = null;
            _resultText = string.Empty;
            _passwordBytes = null;
            Log.Clear();
            Log.Add($"[ui] {_localization["log.started"]}");
            StageIndex = 1;
            RefreshCommands();
            RaiseAll();
        }
        catch (Exception ex)
        {
            CleanupJob();
            _setupError = ex.Message;
            StageIndex = 0;
            RaiseAll();
            RefreshCommands();
        }
    }

    private void Pause()
    {
        if (!CanPause || _handle is null) return;
        try
        {
            _kernel.Pause(_handle);
            _runState = AcxRunStateKind.Paused;
            Log.Add($"[ui] {_localization["log.paused"]}");
            RefreshCommands();
            RaisePropertyChanged(nameof(RunStateText));
        }
        catch (Exception ex) { ShowRuntimeError(ex); }
    }

    private void Resume()
    {
        if (!CanResume || _handle is null) return;
        try
        {
            _kernel.Resume(_handle);
            _runState = AcxRunStateKind.Running;
            Log.Add($"[ui] {_localization["log.resumed"]}");
            RefreshCommands();
            RaisePropertyChanged(nameof(RunStateText));
        }
        catch (Exception ex) { ShowRuntimeError(ex); }
    }

    private void Stop()
    {
        if (!CanStop || _handle is null) return;
        try
        {
            _kernel.Stop(_handle);
            _runState = AcxRunStateKind.Stopped;
            Log.Add($"[ui] {_localization["log.stopped"]}");
            RefreshCommands();
            RaisePropertyChanged(nameof(RunStateText));
        }
        catch (Exception ex) { ShowRuntimeError(ex); }
    }

    private async Task CopyPasswordAsync()
    {
        if (_passwordBytes is null) return;
        if (await _shell.CopyToClipboardAsync(PasswordText))
            Log.Add($"[ui] {_localization["log.copied"]}");
        else
            Log.Add($"[ui] {_localization["log.copy_failed"]}");
    }

    private void OpenFolder()
    {
        if (!string.IsNullOrWhiteSpace(_archivePath)) _shell.OpenContainingFolder(_archivePath);
    }

    private void Reset()
    {
        CleanupJob();
        _outcome = JobOutcomeKind.Pending;
        _terminalLocked = false;
        _runState = AcxRunStateKind.Idle;
        _progressText = string.Empty;
        _progress = null;
        _resultText = string.Empty;
        _passwordBytes = null;
        StageIndex = 0;
        RefreshCommands();
        RaiseAll();
    }

    private void Refresh()
    {
        _probe = _kernel.Probe();
        if (_handle is not null && !_probe.Available) CleanupJob();
        RaiseAll();
        RefreshCommands();
    }

    private void ToggleTheme() =>
        _theme.Set(_theme.Current == ThemeKind.Dark ? ThemeKind.Light : ThemeKind.Dark);

    private void ToggleLanguage() =>
        _localization.SetLanguage(string.Equals(_localization.Language, "zh", StringComparison.Ordinal) ? "en" : "zh");

    private void OnProgress(ProgressSnapshot snapshot)
    {
        _progress = snapshot;
        _progressText = $"{snapshot.Tried}/{snapshot.Total} · {snapshot.Rate:F1}/s · ETA {snapshot.EtaSec}s";
        RaisePropertyChanged(nameof(ProgressText));
        RaisePropertyChanged(nameof(ProgressPercent));
    }

    private void OnHit(byte[] password)
    {
        _passwordBytes = password.ToArray();
        RaisePropertyChanged(nameof(PasswordText));
        RaisePropertyChanged(nameof(PasswordHex));
        RaisePropertyChanged(nameof(HasPassword));
        ((AsyncRelayCommand)CopyPasswordCommand).RaiseCanExecuteChanged();
    }

    private void OnLog(string message)
    {
        Log.Add(message);
        while (Log.Count > 100) Log.RemoveAt(0);
    }

    private void OnFinished(int status)
    {
        if (_terminalLocked) return;
        var lastStatus = AcxStatusMap.FromCode(status);
        try
        {
            if (_handle is not null)
            {
                var snapshot = _kernel.GetStatus(_handle);
                _runState = snapshot.State;
                lastStatus = snapshot.LastStatus;
            }
        }
        catch (Exception ex)
        {
            lastStatus = AcxStatusKind.Internal;
            Log.Add($"[ui] {ex.Message}");
        }

        _outcome = (lastStatus, _runState, _passwordBytes is not null) switch
        {
            (not AcxStatusKind.Ok, _, _) => JobOutcomeKind.Failed,
            (_, AcxRunStateKind.Finished, true) => JobOutcomeKind.Found,
            (_, AcxRunStateKind.Finished, false) => JobOutcomeKind.NotFound,
            (_, AcxRunStateKind.Stopped, _) => JobOutcomeKind.Stopped,
            (_, AcxRunStateKind.Failed, _) => JobOutcomeKind.Failed,
            _ => JobOutcomeKind.NotFound,
        };
        _resultText = _localization[_outcome switch
        {
            JobOutcomeKind.Found => "result.found",
            JobOutcomeKind.NotFound => "result.not_found",
            JobOutcomeKind.Stopped => "result.stopped",
            _ => "result.failed",
        }];
        _terminalLocked = true;
        StageIndex = 2;
        CleanupCheckpoint();
        RefreshCommands();
        RaiseAll();
    }

    private void ShowRuntimeError(Exception ex)
    {
        _terminalLocked = true;
        _outcome = JobOutcomeKind.Failed;
        _resultText = ex.Message;
        if (CanStop)
        {
            try { _kernel.Stop(_handle!); } catch { /* best effort */ }
        }
        CleanupJob();
        StageIndex = 2;
        RefreshCommands();
        RaiseAll();
    }

    private void CleanupJob()
    {
        if (_handle is not null)
        {
            _handle.Dispose();
            _handle = null;
        }
        CleanupCheckpoint();
    }

    private void CleanupCheckpoint()
    {
        _checkpoint?.Dispose();
        _checkpoint = null;
    }

    private void RefreshCommands()
    {
        ((RelayCommand)InspectArchiveCommand).RaiseCanExecuteChanged();
        ((RelayCommand)StartCommand).RaiseCanExecuteChanged();
        ((RelayCommand)PauseCommand).RaiseCanExecuteChanged();
        ((RelayCommand)ResumeCommand).RaiseCanExecuteChanged();
        ((RelayCommand)StopCommand).RaiseCanExecuteChanged();
        ((AsyncRelayCommand)CopyPasswordCommand).RaiseCanExecuteChanged();
        ((RelayCommand)OpenFolderCommand).RaiseCanExecuteChanged();
        ((RelayCommand)RefreshCommand).RaiseCanExecuteChanged();
    }

    private static string EncryptionName(uint code) => code switch
    {
        AcxEncryptionCode.ZipCrypto => "ZipCrypto",
        AcxEncryptionCode.Aes => "AES",
        _ => "Unknown",
    };

    private static string SafePasswordText(byte[] bytes)
    {
        try
        {
            return new UTF8Encoding(false, true).GetString(bytes);
        }
        catch (DecoderFallbackException)
        {
            return Convert.ToHexString(bytes);
        }
    }

    private void OnLocalizationChanged(object? sender, EventArgs e)
    {
        if (_inspection is not null) InspectArchive();
        RaiseAll();
    }

    private void OnThemeChanged(object? sender, EventArgs e) => RaisePropertyChanged(nameof(ThemeLabel));

    private void RaiseAll()
    {
        foreach (var name in new[]
                 {
                     nameof(TitleText), nameof(SubtitleText), nameof(ProductLabel), nameof(VersionLabel),
                     nameof(AbiLibraryLabel), nameof(ProductText), nameof(VersionText),
                     nameof(AbiText), nameof(LibraryPathText), nameof(KernelStatusText), nameof(ErrorText),
                     nameof(HasError), nameof(IntegrityText), nameof(SidecarText), nameof(StageIndex),
                     nameof(ArchivePath), nameof(DictionaryPath), nameof(Threads), nameof(MaxThreads),
                     nameof(ThreadOptions), nameof(IsRunStage), nameof(IsResultStage),
                     nameof(ArchiveInfoText), nameof(SetupErrorText), nameof(HasSetupError),
                     nameof(RunStateText), nameof(ProgressText), nameof(ProgressPercent), nameof(ResultText), nameof(PasswordText),
                     nameof(PasswordHex), nameof(HasPassword), nameof(Outcome), nameof(CanStart),
                     nameof(SetupHeader), nameof(RunHeader), nameof(ResultHeader), nameof(ArchiveLabel),
                     nameof(DictionaryLabel), nameof(ThreadsLabel), nameof(BrowseLabel), nameof(InspectLabel),
                     nameof(StartLabel), nameof(PauseLabel), nameof(ResumeLabel), nameof(StopLabel),
                     nameof(CopyPasswordLabel), nameof(OpenFolderLabel), nameof(ResetLabel),
                     nameof(RefreshLabel), nameof(ThemeLabel), nameof(LanguageLabel), nameof(LogLabel),
                 })
        {
            RaisePropertyChanged(name);
        }
    }
}
