// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

namespace ArchCracker.Desktop.Services;

public enum ThemeKind
{
    Light,
    Dark,
}

public interface IThemeService
{
    ThemeKind Current { get; }
    void Set(ThemeKind theme);
    event EventHandler? ThemeChanged;
}
