// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

namespace ArchCracker.Desktop.Services;

public interface ILocalizationService
{
    string Language { get; }
    IReadOnlyList<string> Languages { get; }
    string this[string key] { get; }
    void SetLanguage(string language);
    event EventHandler? LanguageChanged;
}
