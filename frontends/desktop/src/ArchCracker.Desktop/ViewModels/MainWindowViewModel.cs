// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

using System.Collections.ObjectModel;
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
    private readonly SidecarOptions _sidecar;
    private AcxJobHandle? _handle;
    private KernelProbeResult _probe = new(false, string.Empty, string.Empty, 0, string.Empty,
        AcxStatusKind.Internal, string.Empty, AcxLibraryIntegrity.NotPinned);
    private string _handleText = string.Empty;
    private string _progressText = string.Empty;
    private string _hitText = string.Empty;
    private string _statusText = string.Empty;

    public MainWindowViewModel(
        IKernelService kernel,
        ILocalizationService localization,
        IThemeService theme,
        NativeCallbackRouter callbacks,
        SidecarOptions? sidecar = null)
    {
        _kernel = kernel;
        _localization = localization;
        _theme = theme;
        _callbacks = callbacks;
        _sidecar = sidecar ?? new SidecarOptions(false);
        _callbacks.Progress += OnProgress;
        _callbacks.Hit += OnHit;
        _callbacks.Log += OnLog;
        _callbacks.Finished += OnFinished;
        _localization.LanguageChanged += OnLocalizationChanged;
        _theme.ThemeChanged += OnThemeChanged;

        RefreshCommand = new RelayCommand(Refresh);
        CreateHandleCommand = new RelayCommand(CreateHandle, () => _probe.Available && _handle is null);
        DestroyHandleCommand = new RelayCommand(DestroyHandle, () => _handle is not null);
        ToggleThemeCommand = new RelayCommand(ToggleTheme);
        ToggleLanguageCommand = new RelayCommand(ToggleLanguage);
        Refresh();
    }

    public ICommand RefreshCommand { get; }
    public ICommand CreateHandleCommand { get; }
    public ICommand DestroyHandleCommand { get; }
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
    public string StatusText => _statusText;
    public string HandleText => _handleText;
    public string ProgressText => _progressText;
    public string HitText => _hitText;
    public string RefreshLabel => _localization["view.refresh"];
    public string CreateHandleLabel => _localization["view.create_handle"];
    public string DestroyHandleLabel => _localization["view.destroy_handle"];
    public string ThemeLabel => $"{_localization["view.toggle_theme"]} ({_theme.Current})";
    public string LanguageLabel => _localization["view.toggle_language"];
    public string LogLabel => _localization["view.log"];

    public void Dispose()
    {
        _handle?.Dispose();
        _handle = null;
        _callbacks.Progress -= OnProgress;
        _callbacks.Hit -= OnHit;
        _callbacks.Log -= OnLog;
        _callbacks.Finished -= OnFinished;
        _localization.LanguageChanged -= OnLocalizationChanged;
        _theme.ThemeChanged -= OnThemeChanged;
    }

    private void Refresh()
    {
        _probe = _kernel.Probe();
        _statusText = _probe.Available ? _localization["view.ready"] : _localization["status.unknown"];
        _progressText = string.Empty;
        _hitText = string.Empty;
        Log.Clear();
        if (_handle is not null && !_probe.Available)
        {
            _handle.Dispose();
            _handle = null;
            _handleText = string.Empty;
        }
        RaiseAll();
        ((RelayCommand)CreateHandleCommand).RaiseCanExecuteChanged();
        ((RelayCommand)DestroyHandleCommand).RaiseCanExecuteChanged();
    }

    private void CreateHandle()
    {
        if (_handle is not null) return;
        _handle = _kernel.CreateHandle();
        _handleText = $"0x{_handle.DangerousGetHandle():X}";
        _statusText = _localization["view.ready"];
        RaisePropertyChanged(nameof(HandleText));
        RaisePropertyChanged(nameof(StatusText));
        ((RelayCommand)DestroyHandleCommand).RaiseCanExecuteChanged();
        ((RelayCommand)CreateHandleCommand).RaiseCanExecuteChanged();
    }

    private void DestroyHandle()
    {
        if (_handle is null) return;
        _kernel.DestroyHandle(_handle);
        _handle = null;
        _handleText = string.Empty;
        RaisePropertyChanged(nameof(HandleText));
        ((RelayCommand)DestroyHandleCommand).RaiseCanExecuteChanged();
        ((RelayCommand)CreateHandleCommand).RaiseCanExecuteChanged();
    }

    private void ToggleTheme() =>
        _theme.Set(_theme.Current == ThemeKind.Dark ? ThemeKind.Light : ThemeKind.Dark);

    private void ToggleLanguage() =>
        _localization.SetLanguage(string.Equals(_localization.Language, "zh", StringComparison.Ordinal) ? "en" : "zh");

    private void OnProgress(ProgressSnapshot snapshot)
    {
        _progressText = $"{snapshot.Tried}/{snapshot.Total} · {snapshot.Rate:F1}/s · ETA {snapshot.EtaSec}s";
        RaisePropertyChanged(nameof(ProgressText));
    }

    private void OnHit(string passwordHex)
    {
        _hitText = $"HIT {passwordHex}";
        RaisePropertyChanged(nameof(HitText));
    }

    private void OnLog(string message)
    {
        Log.Add(message);
        while (Log.Count > 100) Log.RemoveAt(0);
    }

    private void OnFinished(int status)
    {
        _statusText = AcxStatusMap.Key(AcxStatusMap.FromCode(status));
        RaisePropertyChanged(nameof(StatusText));
    }

    private void OnLocalizationChanged(object? sender, EventArgs e) => RaiseAll();

    private void OnThemeChanged(object? sender, EventArgs e) => RaisePropertyChanged(nameof(ThemeLabel));

    private void RaiseAll()
    {
        foreach (var name in new[]
                 {
                     nameof(TitleText), nameof(SubtitleText), nameof(ProductLabel), nameof(VersionLabel),
                     nameof(AbiLibraryLabel), nameof(ProductText), nameof(VersionText),
                     nameof(AbiText), nameof(LibraryPathText), nameof(KernelStatusText), nameof(ErrorText),
                     nameof(HasError), nameof(IntegrityText), nameof(SidecarText), nameof(StatusText), nameof(ProgressText), nameof(HitText),
                     nameof(RefreshLabel), nameof(CreateHandleLabel), nameof(DestroyHandleLabel),
                     nameof(ThemeLabel), nameof(LanguageLabel), nameof(LogLabel),
                 })
        {
            RaisePropertyChanged(name);
        }
    }
}
