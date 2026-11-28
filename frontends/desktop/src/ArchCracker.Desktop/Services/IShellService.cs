// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

namespace ArchCracker.Desktop.Services;

public interface IShellService
{
    void OpenContainingFolder(string path);

    Task<bool> CopyToClipboardAsync(string text);
}
