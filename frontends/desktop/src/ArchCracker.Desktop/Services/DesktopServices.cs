// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

using ArchCracker.Desktop.Models;
using ArchCracker.Desktop.Native;
using ArchCracker.Desktop.ViewModels;

namespace ArchCracker.Desktop.Services;

public sealed class DesktopServices : IDisposable
{
    public DesktopServices()
    {
        var i18nDirectory = Path.Combine(AppContext.BaseDirectory, "i18n");
        Localization = new LocalizationService(i18nDirectory);
        Theme = new AvaloniaThemeService();
        Theme.Set(ThemeKind.Dark);
        UiDispatcher = new AvaloniaUiDispatcher();
        Callbacks = new NativeCallbackRouter(UiDispatcher);
        Kernel = new KernelService();
        CallbackBridge = new AcxCallbackBridge(Callbacks);
        Sidecar = SidecarOptions.Load();
        MainWindow = new MainWindowViewModel(Kernel, Localization, Theme, Callbacks, Sidecar);
    }

    public ILocalizationService Localization { get; }
    public IThemeService Theme { get; }
    public IUiDispatcher UiDispatcher { get; }
    public NativeCallbackRouter Callbacks { get; }
    public IKernelService Kernel { get; }
    public AcxCallbackBridge CallbackBridge { get; }
    public SidecarOptions Sidecar { get; }
    public MainWindowViewModel MainWindow { get; }

    public void Dispose()
    {
        MainWindow.Dispose();
        CallbackBridge.Dispose();
    }
}
