// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

using Microsoft.Win32.SafeHandles;

namespace ArchCracker.Desktop.Native;

public sealed class AcxJobHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    internal AcxJobHandle(IntPtr handle) : this(handle, ownsHandle: true) { }

    private AcxJobHandle(IntPtr handle, bool ownsHandle) : base(ownsHandle) => SetHandle(handle);

    /// <summary>Non-owning handle for headless view-model tests.</summary>
    internal static AcxJobHandle CreateTestHandle() => new((IntPtr)1, ownsHandle: false);

    protected override bool ReleaseHandle()
    {
        AcxNative.Destroy(handle);
        SetHandle(IntPtr.Zero);
        return true;
    }
}
