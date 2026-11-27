// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

using System.IO.Compression;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace ArchCracker.Desktop.FfiSmoke;

internal static partial class Native
{
    private const string Library = "acx";

    [LibraryImport(Library, EntryPoint = "acx_abi_version")]
    internal static partial uint AbiVersion();

    [LibraryImport(Library, EntryPoint = "acx_status_name", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial IntPtr StatusName(int status);

    [LibraryImport(Library, EntryPoint = "acx_create")]
    internal static partial int Create(in AcxConfig config, out IntPtr handle);

    [LibraryImport(Library, EntryPoint = "acx_start")]
    internal static partial int Start(IntPtr handle, in AcxAttackSpec spec, in AcxCallbacks callbacks);

    [LibraryImport(Library, EntryPoint = "acx_status")]
    internal static partial int Status(IntPtr handle, ref AcxStatusInfo info);

    [LibraryImport(Library, EntryPoint = "acx_estimate")]
    internal static partial int Estimate(in AcxAttackSpec spec, ref AcxEstimateInfo info);

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
internal unsafe struct AcxInput
{
    public uint StructSize;
    public uint Version;
    public uint Kind;
    public IntPtr Path;
    public nint Fd;
    public IntPtr Uri;
    public fixed ulong Reserved[4];
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct AcxAttackSpec
{
    public uint StructSize;
    public uint Version;
    public AcxInput Input;
    public uint Mode;
    public IntPtr DictionaryPath;
    public IntPtr Masks;
    public uint MaskCount;
    public IntPtr Charset;
    public uint MinLen;
    public uint MaxLen;
    public fixed long Custom[4];
    public IntPtr Rules;
    public uint RuleCount;
    public IntPtr PrefixMask;
    public IntPtr SuffixMask;
    public uint Threads;
    public IntPtr CheckpointPath;
    public byte Resume;
    public IntPtr Encoding;
    public byte Strict;
    public byte RarNoFastReject;
    public byte ReportStats;
    public fixed ulong Reserved[8];
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct AcxCallbacks
{
    public uint StructSize;
    public uint Version;
    public IntPtr OnProgress;
    public IntPtr OnHit;
    public IntPtr OnLog;
    public IntPtr OnFinished;
    public IntPtr User;
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

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct AcxEstimateInfo
{
    public uint StructSize;
    public uint Version;
    public uint Format;
    public uint Reserved32;
    public ulong TotalLow;
    public ulong TotalHigh;
    public byte FitsUsize;
    public byte EncodingVariants;
    private readonly byte _reserved8a;
    private readonly byte _reserved8b;
    public ulong WatermarkBytes;
    public ulong EstimatedPeakBytes;
    public ulong InFlightBatches;
    public double MeasuredRate;
    public ulong EtaSec;
    public fixed ulong Reserved[4];
}

internal sealed class CallbackState
{
    public int Finished;
}

internal static class Program
{
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void FinishedDelegate(IntPtr user, int status);

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

        ValidateSizes();
        var preferred = Path.Combine(Path.GetTempPath(), $"acx-ffi-smoke-{Guid.NewGuid():N}");
        var root = preferred;
        try
        {
            Directory.CreateDirectory(root);
        }
        catch (UnauthorizedAccessException)
        {
            root = Path.Combine(AppContext.BaseDirectory, $"acx-ffi-smoke-{Guid.NewGuid():N}");
            Directory.CreateDirectory(root);
        }
        try
        {
            var source = Path.Combine(root, "source");
            Directory.CreateDirectory(source);
            File.WriteAllText(Path.Combine(source, "hello.txt"), "hello");
            var archive = Path.Combine(root, "plain.zip");
            ZipFile.CreateFromDirectory(source, archive, CompressionLevel.NoCompression, false);
            var dictionary = Path.Combine(root, "dict.txt");
            File.WriteAllText(dictionary, "wrong\n");

            var unmanaged = RunJob(root, archive, dictionary, CallbackModel.UnmanagedCallersOnly);
            var delegateModel = RunJob(root, archive, dictionary, CallbackModel.Delegate);
            Console.WriteLine(
                $"ABI=1 UCO={unmanaged} delegate={delegateModel} " +
                "chosen=UnmanagedCallersOnly");
            return unmanaged && delegateModel ? 0 : 1;
        }
        finally
        {
            Directory.Delete(root, true);
        }
    }

    private static unsafe bool RunJob(string root, string archive, string dictionary, CallbackModel model)
    {
        var checkpoint = Path.Combine(root, $"checkpoint-{model}.acx-checkpoint");
        var archivePtr = Marshal.StringToCoTaskMemUTF8(archive);
        var dictionaryPtr = Marshal.StringToCoTaskMemUTF8(dictionary);
        var checkpointPtr = Marshal.StringToCoTaskMemUTF8(checkpoint);
        var state = new CallbackState();
        var gcHandle = GCHandle.Alloc(state);
        FinishedDelegate? keptDelegate = null;

        try
        {
            var input = new AcxInput
            {
                StructSize = (uint)sizeof(AcxInput),
                Version = 1,
                Kind = 0,
                Path = archivePtr,
                Fd = -1,
                Uri = IntPtr.Zero,
            };
            var spec = new AcxAttackSpec
            {
                StructSize = (uint)sizeof(AcxAttackSpec),
                Version = 1,
                Input = input,
                Mode = 0,
                DictionaryPath = dictionaryPtr,
                Threads = 1,
                CheckpointPath = checkpointPtr,
                ReportStats = 1,
            };

            var estimate = new AcxEstimateInfo
            {
                StructSize = (uint)sizeof(AcxEstimateInfo),
                Version = 1,
            };
            if (Native.Estimate(spec, ref estimate) != 0 || estimate.TotalLow < 1)
            {
                Console.Error.WriteLine($"acx_estimate failed for {model}");
                return false;
            }

            var callbacks = new AcxCallbacks
            {
                StructSize = (uint)sizeof(AcxCallbacks),
                Version = 1,
                User = GCHandle.ToIntPtr(gcHandle),
            };
            unsafe
            {
                if (model == CallbackModel.UnmanagedCallersOnly)
                {
                    callbacks.OnFinished = (IntPtr)(delegate* unmanaged[Cdecl]<IntPtr, int, void>)&OnFinished;
                }
                else
                {
                    keptDelegate = OnFinishedDelegateModel;
                    callbacks.OnFinished = Marshal.GetFunctionPointerForDelegate(keptDelegate);
                }
            }

            var config = new AcxConfig { StructSize = (uint)sizeof(AcxConfig), Version = 1 };
            if (Native.Create(config, out var handle) != 0 || handle == IntPtr.Zero)
            {
                Console.Error.WriteLine($"acx_create failed for {model}");
                return false;
            }

            if (Native.Start(handle, spec, callbacks) != 0)
            {
                Native.Destroy(handle);
                Console.Error.WriteLine($"acx_start failed for {model}");
                return false;
            }

            var info = new AcxStatusInfo { StructSize = (uint)sizeof(AcxStatusInfo), Version = 1 };
            var deadline = DateTime.UtcNow.AddSeconds(15);
            while (true)
            {
                if (Native.Status(handle, ref info) != 0)
                {
                    Native.Destroy(handle);
                    return false;
                }
                if (info.State is not (1 or 2)) break;
                if (DateTime.UtcNow > deadline)
                {
                    Native.Destroy(handle);
                    Console.Error.WriteLine($"timeout for {model}");
                    return false;
                }
                Thread.Sleep(25);
            }

            Native.Destroy(handle);
            GC.KeepAlive(keptDelegate);
            return state.Finished > 0 && info.State is 3 or 4 or 5;
        }
        finally
        {
            gcHandle.Free();
            Marshal.FreeCoTaskMem(archivePtr);
            Marshal.FreeCoTaskMem(dictionaryPtr);
            Marshal.FreeCoTaskMem(checkpointPtr);
        }
    }

    private static void ValidateSizes()
    {
        unsafe
        {
            Expect(sizeof(AcxConfig) == 40, "AcxConfig");
            Expect(sizeof(AcxInput) == 72, "AcxInput");
            Expect(sizeof(AcxAttackSpec) == 296, "AcxAttackSpec");
            Expect(sizeof(AcxCallbacks) == 80, "AcxCallbacks");
            Expect(sizeof(AcxStatusInfo) == 88, "AcxStatusInfo");
            Expect(sizeof(AcxEstimateInfo) == 112, "AcxEstimateInfo");
        }
    }

    private static void Expect(bool condition, string name)
    {
        if (!condition) throw new InvalidOperationException($"bad layout size: {name}");
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void OnFinished(IntPtr user, int status)
    {
        _ = status;
        var state = (CallbackState?)GCHandle.FromIntPtr(user).Target;
        if (state is not null) Interlocked.Increment(ref state.Finished);
    }

    private static void OnFinishedDelegateModel(IntPtr user, int status)
    {
        _ = status;
        var state = (CallbackState?)GCHandle.FromIntPtr(user).Target;
        if (state is not null) Interlocked.Increment(ref state.Finished);
    }

    private static string Read(IntPtr ptr) =>
        ptr == IntPtr.Zero ? string.Empty : Marshal.PtrToStringUTF8(ptr) ?? string.Empty;

    private enum CallbackModel
    {
        UnmanagedCallersOnly,
        Delegate,
    }
}
