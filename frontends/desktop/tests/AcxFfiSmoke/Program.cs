// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

using System.Runtime.InteropServices;
using System.Text;

namespace ArchCracker.Desktop.FfiSmoke;

/// <summary>
/// Compile-and-run smoke test for the C ABI v1 P/Invoke shape. It validates
/// metadata, struct sizes, and create/status/destroy; it does not start a job.
/// </summary>
internal static partial class Native
{
    private const string Library = "acx";

    [LibraryImport(Library, EntryPoint = "acx_abi_version")]
    internal static partial uint AbiVersion();

    [LibraryImport(Library, EntryPoint = "acx_status_name", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr StatusName(int status);

    [LibraryImport(Library, EntryPoint = "acx_create")]
    internal static partial int Create(IntPtr config, out IntPtr handle);

    [LibraryImport(Library, EntryPoint = "acx_status")]
    internal static partial int Status(IntPtr handle, ref AcxStatusInfo info);

    [LibraryImport(Library, EntryPoint = "acx_destroy")]
    internal static partial void Destroy(IntPtr handle);

    [LibraryImport(Library, EntryPoint = "acx_last_error", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr LastError(IntPtr handle);
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct AcxConfig
{
    public uint StructSize;
    public uint Version;
    public fixed ulong Reserved[4];
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct AcxStatusInfo
{
    public uint StructSize;
    public uint Version;
    public uint State;
    public ulong Tried;
    public ulong Total;
    public double Rate;
    public ulong EtaSec;
    public int LastStatus;
    public fixed ulong Reserved[4];
}

internal static class Program
{
    private static int Main(string[] args)
    {
        if (args.Length != 1 || !File.Exists(args[0]))
        {
            Console.Error.WriteLine("usage: AcxFfiSmoke <path-to-acx.dll>");
            return 2;
        }

        NativeLibrary.SetDllImportResolver(typeof(Program).Assembly,
            (name, _, _) => name == "acx" ? NativeLibrary.Load(args[0]) : IntPtr.Zero);

        if (Native.AbiVersion() != 1)
        {
            Console.Error.WriteLine("unexpected ABI version");
            return 1;
        }

        unsafe
        {
            var config = new AcxConfig
            {
                StructSize = (uint)sizeof(AcxConfig),
                Version = 1,
            };
            var status = Native.Create((IntPtr)(&config), out var handle);
            if (status != 0 || handle == IntPtr.Zero)
            {
                Console.Error.WriteLine($"acx_create failed: {status} {Read(Native.LastError(IntPtr.Zero))}");
                return 1;
            }

            var info = new AcxStatusInfo
            {
                StructSize = (uint)sizeof(AcxStatusInfo),
                Version = 1,
            };
            status = Native.Status(handle, ref info);
            Native.Destroy(handle);
            if (status != 0)
            {
                Console.Error.WriteLine($"acx_status failed: {status}");
                return 1;
            }

            Console.WriteLine($"ABI={Native.AbiVersion()} state={info.State} status={Read(Native.StatusName(0))}");
        }

        return 0;
    }

    private static string Read(IntPtr ptr) =>
        ptr == IntPtr.Zero ? string.Empty : Marshal.PtrToStringUTF8(ptr) ?? string.Empty;
}
