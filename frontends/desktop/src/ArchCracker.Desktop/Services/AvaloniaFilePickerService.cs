// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Platform.Storage;

namespace ArchCracker.Desktop.Services;

public sealed class AvaloniaFilePickerService : IFilePickerService
{
    public async Task<string?> PickArchiveAsync() =>
        await PickAsync("Select archive", new[] { "*.zip" });

    public async Task<string?> PickDictionaryAsync() =>
        await PickAsync("Select dictionary", new[] { "*.txt", "*.dic", "*" });

    private static async Task<string?> PickAsync(string title, string[] patterns)
    {
        var window = (Application.Current?.ApplicationLifetime as IClassicDesktopStyleApplicationLifetime)?
            .MainWindow;
        if (window?.StorageProvider is not { CanOpen: true } storage) return null;

        var type = new FilePickerFileType(title) { Patterns = patterns };
        var files = await storage.OpenFilePickerAsync(new FilePickerOpenOptions
        {
            Title = title,
            AllowMultiple = false,
            FileTypeFilter = new[] { type },
        });
        return files.Count == 0 ? null : files[0].TryGetLocalPath();
    }
}
