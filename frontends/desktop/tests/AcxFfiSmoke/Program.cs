// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using ArchCracker.Desktop.Native;

namespace ArchCracker.Desktop.FfiSmoke;

internal static partial class Native
{
    private const string Library = "acx";

    [LibraryImport(Library, EntryPoint = "acx_abi_version")]
    internal static partial uint AbiVersion();

    [LibraryImport(Library, EntryPoint = "acx_inspect", StringMarshalling = StringMarshalling.Utf8)]
    internal static partial int Inspect(string path, ref AcxInspectionInfo info);

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

    [LibraryImport(Library, EntryPoint = "acx_last_error")]
    internal static partial IntPtr LastError(IntPtr handle);
}

internal sealed class CallbackState
{
    public int Finished;
    public int Progress;
    public int Hits;
    public int Logs;
    public string? Password;
}

internal static class Program
{
    private const string Password = "P@ssw0rd123";
    private const string Plaintext = "C ABI v1 integration fixture";

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void ProgressDelegate(IntPtr user, ulong tried, ulong total, double rate, ulong etaSec);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void HitDelegate(IntPtr user, IntPtr password, nuint len);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate void LogDelegate(IntPtr user, int level, IntPtr message);

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
            var archive = Path.Combine(root, "zipcrypto.zip");
            var dictionary = Path.Combine(root, "dict.txt");
            WriteZipCrypto(archive, Password, "hello.txt", Plaintext);
            File.WriteAllText(dictionary, $"wrong\n{Password}\n");

            var unmanaged = RunHit(root, archive, dictionary, CallbackModel.UnmanagedCallersOnly);
            var delegateModel = RunHit(root, archive, dictionary, CallbackModel.Delegate);
            var inspectPath = RunInspect(archive);
            var errorPath = RunMissingArchiveError(root);
            Console.WriteLine(
                $"ABI=1 hit_uco={unmanaged} hit_delegate={delegateModel} inspect={inspectPath} " +
                $"error={errorPath} chosen=UnmanagedCallersOnly");
            return unmanaged && delegateModel && inspectPath && errorPath ? 0 : 1;
        }
        finally
        {
            if (Environment.GetEnvironmentVariable("ACX_SMOKE_KEEP") == "1")
            {
                Console.Error.WriteLine($"smoke fixtures kept at {root}");
            }
            else
            {
                Directory.Delete(root, true);
            }
        }
    }

    private static unsafe bool RunHit(string root, string archive, string dictionary, CallbackModel model)
    {
        var checkpoint = Path.Combine(root, $"hit-checkpoint-{model}.acx-checkpoint");
        var archivePtr = Marshal.StringToCoTaskMemUTF8(archive);
        var dictionaryPtr = Marshal.StringToCoTaskMemUTF8(dictionary);
        var checkpointPtr = Marshal.StringToCoTaskMemUTF8(checkpoint);
        var state = new CallbackState();
        var gcHandle = GCHandle.Alloc(state);
        ProgressDelegate? keptProgress = null;
        HitDelegate? keptHit = null;
        LogDelegate? keptLog = null;
        FinishedDelegate? keptFinished = null;

        try
        {
            var spec = MakeSpec(archivePtr, dictionaryPtr, checkpointPtr);
            var estimate = new AcxEstimateInfo { StructSize = (uint)sizeof(AcxEstimateInfo), Version = 1 };
            if (Native.Estimate(spec, ref estimate) != 0 || estimate.TotalLow < 2)
            {
                Console.Error.WriteLine(
                    $"acx_estimate failed for {model}: {Read(Native.LastError(IntPtr.Zero))}");
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
                    callbacks.OnProgress = (IntPtr)(delegate* unmanaged[Cdecl]<IntPtr, ulong, ulong, double, ulong, void>)&OnProgress;
                    callbacks.OnHit = (IntPtr)(delegate* unmanaged[Cdecl]<IntPtr, IntPtr, nuint, void>)&OnHit;
                    callbacks.OnLog = (IntPtr)(delegate* unmanaged[Cdecl]<IntPtr, int, IntPtr, void>)&OnLog;
                    callbacks.OnFinished = (IntPtr)(delegate* unmanaged[Cdecl]<IntPtr, int, void>)&OnFinished;
                }
                else
                {
                    keptProgress = OnProgressDelegateModel;
                    keptHit = OnHitDelegateModel;
                    keptLog = OnLogDelegateModel;
                    keptFinished = OnFinishedDelegateModel;
                    callbacks.OnProgress = Marshal.GetFunctionPointerForDelegate(keptProgress);
                    callbacks.OnHit = Marshal.GetFunctionPointerForDelegate(keptHit);
                    callbacks.OnLog = Marshal.GetFunctionPointerForDelegate(keptLog);
                    callbacks.OnFinished = Marshal.GetFunctionPointerForDelegate(keptFinished);
                }
            }

            var config = new AcxConfig { StructSize = (uint)sizeof(AcxConfig), Version = 1 };
            if (Native.Create(config, out var handle) != 0 || handle == IntPtr.Zero)
            {
                Console.Error.WriteLine($"acx_create failed for {model}");
                return false;
            }

            var startStatus = Native.Start(handle, spec, callbacks);
            if (startStatus != 0)
            {
                Console.Error.WriteLine($"acx_start failed for {model}: {startStatus} {Read(Native.LastError(handle))}");
                Native.Destroy(handle);
                return false;
            }

            var info = new AcxStatusInfo { StructSize = (uint)sizeof(AcxStatusInfo), Version = 1 };
            var deadline = DateTime.UtcNow.AddSeconds(15);
            while (true)
            {
                if (Native.Status(handle, ref info) != 0)
                {
                    Console.Error.WriteLine($"acx_status failed for {model}: {Read(Native.LastError(handle))}");
                    Native.Destroy(handle);
                    return false;
                }
                if (info.State is not (1 or 2)) break;
                if (DateTime.UtcNow > deadline)
                {
                    Console.Error.WriteLine($"timeout for {model}");
                    Native.Destroy(handle);
                    return false;
                }
                Thread.Sleep(25);
            }

            Native.Destroy(handle);
            GC.KeepAlive(keptProgress);
            GC.KeepAlive(keptHit);
            GC.KeepAlive(keptLog);
            GC.KeepAlive(keptFinished);
            return state.Hits == 1
                && state.Password == Password
                && state.Progress >= 1
                && state.Logs >= 1
                && state.Finished == 1
                && info.State == 4
                && info.LastStatus == 0;
        }
        finally
        {
            gcHandle.Free();
            Marshal.FreeCoTaskMem(archivePtr);
            Marshal.FreeCoTaskMem(dictionaryPtr);
            Marshal.FreeCoTaskMem(checkpointPtr);
        }
    }

    private static unsafe bool RunInspect(string archive)
    {
        var info = AcxInspectionInfo.Create();
        var status = Native.Inspect(archive, ref info);
        return status == 0
            && info.Format == 0
            && info.Encryption == 1
            && info.EntryCount == 1
            && info.SelectedIndex != ulong.MaxValue
            && info.HasVerificationTarget == 1;
    }

    private static unsafe bool RunMissingArchiveError(string root)
    {
        var missing = Path.Combine(root, "missing.zip");
        var dictionary = Path.Combine(root, "error-dict.txt");
        var checkpoint = Path.Combine(root, "error-checkpoint.acx-checkpoint");
        File.WriteAllText(dictionary, "wrong\n");
        var missingPtr = Marshal.StringToCoTaskMemUTF8(missing);
        var dictionaryPtr = Marshal.StringToCoTaskMemUTF8(dictionary);
        var checkpointPtr = Marshal.StringToCoTaskMemUTF8(checkpoint);

        try
        {
            var spec = MakeSpec(missingPtr, dictionaryPtr, checkpointPtr);
            var config = new AcxConfig { StructSize = (uint)sizeof(AcxConfig), Version = 1 };
            if (Native.Create(config, out var handle) != 0 || handle == IntPtr.Zero)
            {
                Console.Error.WriteLine("acx_create failed for error path");
                return false;
            }

            var noCallbacks = new AcxCallbacks
            {
                StructSize = (uint)sizeof(AcxCallbacks),
                Version = 1,
            };
            var startStatus = Native.Start(handle, spec, noCallbacks);
            var lastError = Read(Native.LastError(handle));
            var info = new AcxStatusInfo { StructSize = (uint)sizeof(AcxStatusInfo), Version = 1 };
            var statusResult = Native.Status(handle, ref info);
            Native.Destroy(handle);
            return startStatus == 2
                && statusResult == 0
                && info.State == 0
                && info.LastStatus == 2
                && !string.IsNullOrEmpty(lastError);
        }
        finally
        {
            Marshal.FreeCoTaskMem(missingPtr);
            Marshal.FreeCoTaskMem(dictionaryPtr);
            Marshal.FreeCoTaskMem(checkpointPtr);
        }
    }

    private static unsafe AcxAttackSpec MakeSpec(IntPtr archivePtr, IntPtr dictionaryPtr, IntPtr checkpointPtr)
    {
        return new AcxAttackSpec
        {
            StructSize = (uint)sizeof(AcxAttackSpec),
            Version = 1,
            Input = new AcxInput
            {
                StructSize = (uint)sizeof(AcxInput),
                Version = 1,
                Kind = 0,
                Path = archivePtr,
                Fd = -1,
                Uri = IntPtr.Zero,
            },
            Mode = 0,
            DictionaryPath = dictionaryPtr,
            Threads = 1,
            CheckpointPath = checkpointPtr,
            ReportStats = 1,
        };
    }

    private static void WriteZipCrypto(string path, string password, string entryName, string plaintext)
    {
        var name = Encoding.UTF8.GetBytes(entryName);
        var data = Encoding.UTF8.GetBytes(plaintext);
        var crc = Crc32(data);
        var encrypted = EncryptZipCrypto(data, password, crc);
        var localHeaderSize = 30u + (uint)name.Length;
        var descriptorSize = 16u;
        var centralOffset = localHeaderSize + (uint)encrypted.Length + descriptorSize;
        var centralSize = 46u + (uint)name.Length;

        using var stream = File.Create(path);
        using var writer = new BinaryWriter(stream);

        writer.Write(0x04034b50u);
        writer.Write((ushort)20);
        writer.Write((ushort)9); // encrypted + data descriptor
        writer.Write((ushort)0); // stored
        writer.Write((ushort)0); // time
        writer.Write((ushort)0x21); // date: 1980-01-01
        writer.Write(0u); // CRC in descriptor
        writer.Write(0u); // compressed size in descriptor
        writer.Write(0u); // uncompressed size in descriptor
        writer.Write((ushort)name.Length);
        writer.Write((ushort)0);
        writer.Write(name);
        writer.Write(encrypted);

        writer.Write(0x08074b50u);
        writer.Write(crc);
        writer.Write((uint)encrypted.Length);
        writer.Write((uint)data.Length);

        writer.Write(0x02014b50u);
        writer.Write((ushort)20);
        writer.Write((ushort)20);
        writer.Write((ushort)9);
        writer.Write((ushort)0);
        writer.Write((ushort)0); // time
        writer.Write((ushort)0x21); // date
        writer.Write(crc);
        writer.Write((uint)encrypted.Length);
        writer.Write((uint)data.Length);
        writer.Write((ushort)name.Length);
        writer.Write((ushort)0);
        writer.Write((ushort)0);
        writer.Write((ushort)0);
        writer.Write((ushort)0);
        writer.Write(0u);
        writer.Write(0u); // relative offset of this entry's local header
        writer.Write(name);

        writer.Write(0x06054b50u);
        writer.Write((ushort)0);
        writer.Write((ushort)0);
        writer.Write((ushort)1);
        writer.Write((ushort)1);
        writer.Write(centralSize);
        writer.Write(centralOffset);
        writer.Write((ushort)0);
    }

    private static byte[] EncryptZipCrypto(byte[] data, string password, uint crc)
    {
        uint key0 = 0x12345678, key1 = 0x23456789, key2 = 0x34567890;
        foreach (var value in Encoding.ASCII.GetBytes(password))
        {
            UpdateKey(value);
        }

        var result = new byte[12 + data.Length];
        for (var index = 0; index < 11; index++)
        {
            result[index] = Encrypt((byte)index);
        }
        // General-purpose bit 3 is set, so validators use the high byte of
        // the MS-DOS modification time; it is zero in this deterministic fixture.
        result[11] = Encrypt(0);
        for (var index = 0; index < data.Length; index++)
        {
            result[12 + index] = Encrypt(data[index]);
        }
        return result;

        byte Encrypt(byte plaintext)
        {
            var temp = key2 | 2;
            var cipher = (byte)(((temp * (temp ^ 1)) >> 8) & 0xff);
            UpdateKey(plaintext);
            return (byte)(plaintext ^ cipher);
        }

        void UpdateKey(byte value)
        {
            key0 = Crc32Step(key0, value);
            key1 = unchecked((key1 + (key0 & 0xff)) * 134775813 + 1);
            key2 = Crc32Step(key2, (byte)(key1 >> 24));
        }
    }

    private static uint Crc32(byte[] data)
    {
        var crc = 0xffffffffu;
        foreach (var value in data)
        {
            crc = Crc32Step(crc, value);
        }
        return crc ^ 0xffffffffu;
    }

    private static uint Crc32Step(uint crc, byte value)
    {
        crc ^= value;
        for (var bit = 0; bit < 8; bit++)
        {
            crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xedb88320u : crc >> 1;
        }
        return crc;
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
            Expect(sizeof(AcxInspectionInfo) == 72, "AcxInspectionInfo");
        }
    }

    private static void Expect(bool condition, string name)
    {
        if (!condition) throw new InvalidOperationException($"bad layout size: {name}");
    }

    private static string Read(IntPtr ptr) =>
        ptr == IntPtr.Zero ? string.Empty : Marshal.PtrToStringUTF8(ptr) ?? string.Empty;

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void OnProgress(IntPtr user, ulong tried, ulong total, double rate, ulong etaSec)
    {
        var state = (CallbackState?)GCHandle.FromIntPtr(user).Target;
        if (state is not null) Interlocked.Increment(ref state.Progress);
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static unsafe void OnHit(IntPtr user, IntPtr password, nuint len)
    {
        var state = (CallbackState?)GCHandle.FromIntPtr(user).Target;
        if (state is null) return;
        var bytes = new byte[(int)len];
        Marshal.Copy(password, bytes, 0, bytes.Length);
        state.Password = Encoding.UTF8.GetString(bytes);
        Interlocked.Increment(ref state.Hits);
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void OnLog(IntPtr user, int level, IntPtr message)
    {
        var state = (CallbackState?)GCHandle.FromIntPtr(user).Target;
        if (state is not null) Interlocked.Increment(ref state.Logs);
    }

    [UnmanagedCallersOnly(CallConvs = [typeof(CallConvCdecl)])]
    private static void OnFinished(IntPtr user, int status)
    {
        var state = (CallbackState?)GCHandle.FromIntPtr(user).Target;
        if (state is not null) Interlocked.Increment(ref state.Finished);
    }

    private static void OnProgressDelegateModel(IntPtr user, ulong tried, ulong total, double rate, ulong etaSec)
    {
        var state = (CallbackState?)GCHandle.FromIntPtr(user).Target;
        if (state is not null) Interlocked.Increment(ref state.Progress);
    }

    private static unsafe void OnHitDelegateModel(IntPtr user, IntPtr password, nuint len)
    {
        var state = (CallbackState?)GCHandle.FromIntPtr(user).Target;
        if (state is null) return;
        var bytes = new byte[(int)len];
        Marshal.Copy(password, bytes, 0, bytes.Length);
        state.Password = Encoding.UTF8.GetString(bytes);
        Interlocked.Increment(ref state.Hits);
    }

    private static void OnLogDelegateModel(IntPtr user, int level, IntPtr message)
    {
        var state = (CallbackState?)GCHandle.FromIntPtr(user).Target;
        if (state is not null) Interlocked.Increment(ref state.Logs);
    }

    private static void OnFinishedDelegateModel(IntPtr user, int status)
    {
        var state = (CallbackState?)GCHandle.FromIntPtr(user).Target;
        if (state is not null) Interlocked.Increment(ref state.Finished);
    }

    private enum CallbackModel
    {
        UnmanagedCallersOnly,
        Delegate,
    }
}
