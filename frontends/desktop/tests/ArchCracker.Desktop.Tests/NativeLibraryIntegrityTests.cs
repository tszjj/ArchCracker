// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

using System.Security.Cryptography;
using ArchCracker.Desktop.Native;

namespace ArchCracker.Desktop.Tests;

public sealed class NativeLibraryIntegrityTests
{
    [Fact]
    public void MissingPinIsNotPinned()
    {
        var path = WriteTempLibrary();
        try
        {
            Assert.Equal(AcxLibraryIntegrity.NotPinned, AcxNative.VerifyLibrary(path));
        }
        finally
        {
            Directory.Delete(Path.GetDirectoryName(path)!, true);
        }
    }

    [Fact]
    public void MatchingPinIsVerified()
    {
        var path = WriteTempLibrary();
        try
        {
            File.WriteAllText(path + ".sha256",
                Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))) + "  acx.dll\n");
            Assert.Equal(AcxLibraryIntegrity.Verified, AcxNative.VerifyLibrary(path));
        }
        finally
        {
            Directory.Delete(Path.GetDirectoryName(path)!, true);
        }
    }

    [Fact]
    public void WrongPinIsMismatch()
    {
        var path = WriteTempLibrary();
        try
        {
            File.WriteAllText(path + ".sha256", new string('0', 64));
            Assert.Equal(AcxLibraryIntegrity.Mismatch, AcxNative.VerifyLibrary(path));
        }
        finally
        {
            Directory.Delete(Path.GetDirectoryName(path)!, true);
        }
    }

    private static string WriteTempLibrary()
    {
        var preferred = Path.Combine(Path.GetTempPath(), $"acx-integrity-{Guid.NewGuid():N}");
        string directory;
        try
        {
            Directory.CreateDirectory(preferred);
            directory = preferred;
        }
        catch (UnauthorizedAccessException)
        {
            directory = Path.Combine(AppContext.BaseDirectory, $"acx-integrity-{Guid.NewGuid():N}");
            Directory.CreateDirectory(directory);
        }

        var path = Path.Combine(directory, "acx.dll");
        File.WriteAllText(path, "not a real dll");
        return path;
    }
}
