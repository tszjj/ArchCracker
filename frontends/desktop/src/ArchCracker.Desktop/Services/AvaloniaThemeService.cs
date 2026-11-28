// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

using Avalonia;

namespace ArchCracker.Desktop.Services;

public sealed class AvaloniaThemeService : IThemeService
{
    public ThemeKind Current { get; private set; } = ThemeKind.Dark;

    public event EventHandler? ThemeChanged;

    public void Set(ThemeKind theme)
    {
        Current = theme;
        if (Application.Current is not null)
        {
            Application.Current.RequestedThemeVariant = theme == ThemeKind.Dark
                ? Avalonia.Styling.ThemeVariant.Dark
                : Avalonia.Styling.ThemeVariant.Light;
        }
        ThemeChanged?.Invoke(this, EventArgs.Empty);
    }
}
