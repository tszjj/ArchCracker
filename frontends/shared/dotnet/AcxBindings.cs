// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

using System.Runtime.InteropServices;

namespace ArchCracker.Desktop.Native;

[StructLayout(LayoutKind.Sequential)]
public unsafe struct AcxConfig
{
    public uint StructSize;
    public uint Version;
    public fixed ulong Reserved[4];

    public static AcxConfig Create() => new()
    {
        StructSize = (uint)sizeof(AcxConfig),
        Version = 1,
    };
}

[StructLayout(LayoutKind.Sequential)]
public unsafe struct AcxInput
{
    public uint StructSize;
    public uint Version;
    public uint Kind;
    public IntPtr Path;
    public nint Fd;
    public IntPtr Uri;
    public fixed ulong Reserved[4];

    public static AcxInput FromPath(string path) => new()
    {
        StructSize = (uint)sizeof(AcxInput),
        Version = 1,
        Kind = 0,
        Path = Marshal.StringToCoTaskMemUTF8(path),
        Fd = -1,
        Uri = IntPtr.Zero,
    };

    public void Free()
    {
        if (Path != IntPtr.Zero) Marshal.FreeCoTaskMem(Path);
        if (Uri != IntPtr.Zero) Marshal.FreeCoTaskMem(Uri);
        Path = IntPtr.Zero;
        Uri = IntPtr.Zero;
    }
}

[StructLayout(LayoutKind.Sequential)]
public unsafe struct AcxAttackSpec
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
    public IntPtr Custom0;
    public IntPtr Custom1;
    public IntPtr Custom2;
    public IntPtr Custom3;
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

    public static AcxAttackSpec Create(AcxInput input) => new()
    {
        StructSize = (uint)sizeof(AcxAttackSpec),
        Version = 1,
        Input = input,
        Threads = 1,
    };
}

[StructLayout(LayoutKind.Sequential)]
public unsafe struct AcxCallbacks
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
public unsafe struct AcxStatusInfo
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

    public static AcxStatusInfo Create() => new()
    {
        StructSize = (uint)sizeof(AcxStatusInfo),
        Version = 1,
    };
}

[StructLayout(LayoutKind.Sequential)]
public unsafe struct AcxEstimateInfo
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

    public static AcxEstimateInfo Create() => new()
    {
        StructSize = (uint)sizeof(AcxEstimateInfo),
        Version = 1,
    };
}
