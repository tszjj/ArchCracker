// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

namespace ArchCracker.Shared;

public enum AcxStatusKind
{
    Ok = 0,
    InvalidArgument = 1,
    Io = 2,
    Unsupported = 3,
    Archive = 4,
    MissingVolume = 5,
    Cancelled = 6,
    Internal = 7,
    Panic = 8,
    Unknown = 9,
}

public enum AcxRunStateKind
{
    Idle = 0,
    Running = 1,
    Paused = 2,
    Stopped = 3,
    Finished = 4,
    Failed = 5,
    Unknown = 6,
}

public static class AcxStatusMap
{
    public static AcxStatusKind FromCode(int code) =>
        Enum.IsDefined(typeof(AcxStatusKind), code) ? (AcxStatusKind)code : AcxStatusKind.Unknown;

    public static AcxRunStateKind RunStateFromCode(uint code) =>
        code <= (uint)AcxRunStateKind.Failed ? (AcxRunStateKind)code : AcxRunStateKind.Unknown;

    public static string Key(AcxStatusKind kind) => kind switch
    {
        AcxStatusKind.Ok => "status.ok",
        AcxStatusKind.InvalidArgument => "status.invalid_argument",
        AcxStatusKind.Io => "status.io",
        AcxStatusKind.Unsupported => "status.unsupported",
        AcxStatusKind.Archive => "status.archive",
        AcxStatusKind.MissingVolume => "status.missing_volume",
        AcxStatusKind.Cancelled => "status.cancelled",
        AcxStatusKind.Internal => "status.internal",
        AcxStatusKind.Panic => "status.panic",
        _ => "status.unknown",
    };
}
