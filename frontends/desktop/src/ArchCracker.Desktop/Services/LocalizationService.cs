// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

using System.Text.Json;

namespace ArchCracker.Desktop.Services;

public sealed class LocalizationService : ILocalizationService
{
    private readonly string _directory;
    private readonly Dictionary<string, Dictionary<string, string>> _catalogs = new(StringComparer.Ordinal);
    private Dictionary<string, string> _current = new(StringComparer.Ordinal);

    public LocalizationService(string directory)
    {
        _directory = directory;
        foreach (var path in Directory.EnumerateFiles(directory, "*.json"))
        {
            var language = Path.GetFileNameWithoutExtension(path);
            var json = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(path))
                       ?? new Dictionary<string, string>(StringComparer.Ordinal);
            _catalogs[language] = new Dictionary<string, string>(json, StringComparer.Ordinal);
        }
        Languages = _catalogs.Keys.OrderBy(x => x, StringComparer.Ordinal).ToArray();
        SetLanguage(Languages.Contains("zh", StringComparer.Ordinal) ? "zh" : Languages.FirstOrDefault() ?? "en");
    }

    public string Language { get; private set; } = string.Empty;

    public IReadOnlyList<string> Languages { get; }

    public string this[string key] => _current.TryGetValue(key, out var value) ? value : key;

    public event EventHandler? LanguageChanged;

    public void SetLanguage(string language)
    {
        if (!_catalogs.TryGetValue(language, out var catalog))
            throw new ArgumentException($"Unknown language: {language}", nameof(language));
        Language = language;
        _current = catalog;
        LanguageChanged?.Invoke(this, EventArgs.Empty);
    }
}
