// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

using ArchCracker.Desktop.Services;
using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;

namespace ArchCracker.Desktop;

public partial class App : Application
{
    private DesktopServices? _services;

    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        _services = new DesktopServices();
        DataContext = _services.MainWindow;

        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            desktop.MainWindow = new Views.MainWindow { DataContext = _services.MainWindow };
            desktop.Exit += (_, _) => _services.Dispose();
        }

        base.OnFrameworkInitializationCompleted();
    }
}
