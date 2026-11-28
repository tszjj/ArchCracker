// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

namespace ArchCracker.Desktop.Services;

public interface IUiDispatcher
{
    void Post(Action action);
}
