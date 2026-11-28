// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

namespace ArchCracker.Desktop.Services;

public sealed class TempCheckpoint : IDisposable
{
    private TempCheckpoint(string path) => Path = path;

    public string Path { get; }

    public static TempCheckpoint Create()
    {
        var name = $"acx-gui-{Guid.NewGuid():N}.acx-checkpoint";
        var preferred = System.IO.Path.Combine(System.IO.Path.GetTempPath(), name);
        string path;
        try
        {
            using var file = File.Create(preferred);
            path = preferred;
        }
        catch (UnauthorizedAccessException)
        {
            path = System.IO.Path.Combine(AppContext.BaseDirectory, name);
            using var file = File.Create(path);
        }
        return new TempCheckpoint(path);
    }

    public void Dispose()
    {
        try
        {
            File.Delete(this.Path);
        }
        catch (IOException)
        {
            // Temporary checkpoint cleanup is best-effort.
        }
        catch (UnauthorizedAccessException)
        {
            // Temporary checkpoint cleanup is best-effort.
        }
    }
}
