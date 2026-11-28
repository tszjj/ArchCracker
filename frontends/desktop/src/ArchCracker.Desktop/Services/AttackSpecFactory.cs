// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

using System.Runtime.InteropServices;
using ArchCracker.Desktop.Native;

namespace ArchCracker.Desktop.Services;

public static class AttackSpecFactory
{
    public static AcxAttackSpec CreateDictionary(
        string archivePath,
        string dictionaryPath,
        string checkpointPath,
        uint threads)
    {
        var input = AcxInput.FromPath(archivePath);
        var spec = AcxAttackSpec.Create(input);
        spec.Mode = 0;
        spec.DictionaryPath = Marshal.StringToCoTaskMemUTF8(dictionaryPath);
        spec.CheckpointPath = Marshal.StringToCoTaskMemUTF8(checkpointPath);
        spec.Threads = threads;
        return spec;
    }

    public static void Free(AcxAttackSpec spec)
    {
        spec.Input.Free();
        if (spec.DictionaryPath != IntPtr.Zero) Marshal.FreeCoTaskMem(spec.DictionaryPath);
        if (spec.CheckpointPath != IntPtr.Zero) Marshal.FreeCoTaskMem(spec.CheckpointPath);
        spec.DictionaryPath = IntPtr.Zero;
        spec.CheckpointPath = IntPtr.Zero;
    }
}
