// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

using System.Diagnostics;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Input.Platform;

namespace ArchCracker.Desktop.Services;

public sealed class DesktopShellService : IShellService
{
    public void OpenContainingFolder(string path)
    {
        var directory = Path.GetDirectoryName(Path.GetFullPath(path));
        if (string.IsNullOrWhiteSpace(directory) || !Directory.Exists(directory)) return;
        Process.Start(new ProcessStartInfo
        {
            FileName = "explorer.exe",
            Arguments = $"\"{directory}\"",
            UseShellExecute = true,
        });
    }

    public async Task<bool> CopyToClipboardAsync(string text)
    {
        var window = (Application.Current?.ApplicationLifetime as IClassicDesktopStyleApplicationLifetime)?
            .MainWindow;
        var clipboard = TopLevel.GetTopLevel(window)?.Clipboard;
        if (clipboard is null) return false;
        await clipboard.SetTextAsync(text);
        return true;
    }
}
