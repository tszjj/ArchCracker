// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace ArchCracker.Desktop.Native;

public enum AcxLibraryIntegrity
{
    NotPinned,
    Verified,
    Mismatch,
}

public static partial class AcxNative
{
    public const uint ExpectedAbiVersion = 1;
    private const string Library = "acx";

    private static string? _libraryPath;

    static AcxNative()
    {
        NativeLibrary.SetDllImportResolver(typeof(AcxNative).Assembly, Resolve);
    }

    public static string ResolveLibraryPath(string? explicitPath = null)
    {
        if (!string.IsNullOrWhiteSpace(explicitPath))
        {
            var full = Path.GetFullPath(explicitPath);
            if (!File.Exists(full)) throw new FileNotFoundException("Native library not found", full);
            return full;
        }

        var besideApp = Path.Combine(AppContext.BaseDirectory, "acx.dll");
        if (File.Exists(besideApp)) return besideApp;

        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            foreach (var relative in new[]
                     {
                         Path.Combine("core", "target", "release", "acx.dll"),
                         Path.Combine("core", "target", "debug", "acx.dll"),
                     })
            {
                var candidate = Path.Combine(directory.FullName, relative);
                if (File.Exists(candidate)) return candidate;
            }
            directory = directory.Parent;
        }

        throw new FileNotFoundException(
            "acx.dll was not found beside the application or in core/target/debug", besideApp);
    }

    public static void Configure(string? libraryPath = null)
    {
        _libraryPath = ResolveLibraryPath(libraryPath);
    }

    public static AcxLibraryIntegrity VerifyLibrary(string path)
    {
        var pin = path + ".sha256";
        if (!File.Exists(pin)) return AcxLibraryIntegrity.NotPinned;
        var expected = File.ReadAllText(pin).Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries)[0];
        var actual = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));
        return string.Equals(expected, actual, StringComparison.OrdinalIgnoreCase)
            ? AcxLibraryIntegrity.Verified
            : AcxLibraryIntegrity.Mismatch;
    }

    private static IntPtr Resolve(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (libraryName != Library) return IntPtr.Zero;
        if (!string.IsNullOrWhiteSpace(_libraryPath) && File.Exists(_libraryPath))
            return NativeLibrary.Load(_libraryPath);

        var besideApp = Path.Combine(AppContext.BaseDirectory, "acx.dll");
        return File.Exists(besideApp) ? NativeLibrary.Load(besideApp) : IntPtr.Zero;
    }

    public static string CopyUtf8(IntPtr pointer) =>
        pointer == IntPtr.Zero ? string.Empty : Marshal.PtrToStringUTF8(pointer) ?? string.Empty;

    [LibraryImport(Library, EntryPoint = "acx_abi_version")]
    public static partial uint AbiVersion();

    [LibraryImport(Library, EntryPoint = "acx_product")]
    public static partial IntPtr Product();

    [LibraryImport(Library, EntryPoint = "acx_version")]
    public static partial IntPtr Version();

    [LibraryImport(Library, EntryPoint = "acx_create")]
    public static partial int Create(in AcxConfig config, out IntPtr handle);

    [LibraryImport(Library, EntryPoint = "acx_destroy")]
    public static partial void Destroy(IntPtr handle);

    [LibraryImport(Library, EntryPoint = "acx_start")]
    public static partial int Start(AcxJobHandle handle, in AcxAttackSpec spec, in AcxCallbacks callbacks);

    [LibraryImport(Library, EntryPoint = "acx_pause")]
    public static partial int Pause(AcxJobHandle handle);

    [LibraryImport(Library, EntryPoint = "acx_resume")]
    public static partial int Resume(AcxJobHandle handle);

    [LibraryImport(Library, EntryPoint = "acx_stop")]
    public static partial int Stop(AcxJobHandle handle);

    [LibraryImport(Library, EntryPoint = "acx_status")]
    public static partial int Status(AcxJobHandle handle, ref AcxStatusInfo info);

    [LibraryImport(Library, EntryPoint = "acx_estimate")]
    public static partial int Estimate(in AcxAttackSpec spec, ref AcxEstimateInfo info);

    [LibraryImport(Library, EntryPoint = "acx_last_error")]
    public static partial IntPtr LastError(IntPtr handle);
}
