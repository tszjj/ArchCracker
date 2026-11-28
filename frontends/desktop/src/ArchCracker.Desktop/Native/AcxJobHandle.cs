// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

using Microsoft.Win32.SafeHandles;

namespace ArchCracker.Desktop.Native;

public sealed class AcxJobHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    internal AcxJobHandle(IntPtr handle) : base(ownsHandle: true) => SetHandle(handle);

    protected override bool ReleaseHandle()
    {
        AcxNative.Destroy(handle);
        SetHandle(IntPtr.Zero);
        return true;
    }
}
