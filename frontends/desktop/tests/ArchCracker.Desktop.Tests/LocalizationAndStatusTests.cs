// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

using ArchCracker.Desktop.Services;
using ArchCracker.Shared;
using System.Text.Json;

namespace ArchCracker.Desktop.Tests;

public sealed class LocalizationAndStatusTests
{
    [Fact]
    public void LocalizationCatalogsHaveSameKeys()
    {
        var service = new LocalizationService(Path.Combine(AppContext.BaseDirectory, "i18n"));
        Assert.Contains("en", service.Languages);
        Assert.Contains("zh", service.Languages);

        var keys = ReadKeys("en.json");
        Assert.Equal(keys, ReadKeys("zh.json"));

        foreach (var key in keys)
        {
            Assert.NotEqual(key, service[key]);
        }

        service.SetLanguage("en");
        Assert.Equal("中文", service["view.toggle_language"]);
    }

    [Fact]
    public void StatusMapCoversAllV1Codes()
    {
        for (var code = 0; code <= 8; code++)
        {
            var kind = AcxStatusMap.FromCode(code);
            Assert.NotEqual(AcxStatusKind.Unknown, kind);
            Assert.StartsWith("status.", AcxStatusMap.Key(kind));
        }

        Assert.Equal(AcxStatusKind.Unknown, AcxStatusMap.FromCode(9));
        Assert.Equal(AcxStatusKind.Unknown, AcxStatusMap.FromCode(99));
        Assert.Equal(AcxRunStateKind.Finished, AcxStatusMap.RunStateFromCode(4));
    }

    private static HashSet<string> ReadKeys(string file)
    {
        var path = Path.Combine(AppContext.BaseDirectory, "i18n", file);
        var json = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(path));
        Assert.NotNull(json);
        return json.Keys.ToHashSet(StringComparer.Ordinal);
    }
}
