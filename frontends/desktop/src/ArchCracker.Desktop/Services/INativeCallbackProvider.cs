// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

using ArchCracker.Desktop.Native;

namespace ArchCracker.Desktop.Services;

public interface INativeCallbackProvider
{
    AcxCallbacks Callbacks { get; }
}
