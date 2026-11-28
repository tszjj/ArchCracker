// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

namespace ArchCracker.Desktop.Models;

/// <summary>
/// W3-002 reserves the sidecar switch only. A real crash-isolated process is
/// P2 and is not started by the GUI.
/// </summary>
public sealed record SidecarOptions(bool Enabled)
{
    public static SidecarOptions Load() => new(
        bool.TryParse(Environment.GetEnvironmentVariable("ACX_DESKTOP_SIDECAR"), out var enabled) && enabled);
}
