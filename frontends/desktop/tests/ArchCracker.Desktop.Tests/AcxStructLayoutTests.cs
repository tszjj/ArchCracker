// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

using System.Runtime.InteropServices;
using ArchCracker.Desktop.Native;

namespace ArchCracker.Desktop.Tests;

public sealed class AcxStructLayoutTests
{
    [Fact]
    public void V1StructSizesMatchFrozenLayout()
    {
        unsafe
        {
            Assert.Equal(40, sizeof(AcxConfig));
            Assert.Equal(72, sizeof(AcxInput));
            Assert.Equal(296, sizeof(AcxAttackSpec));
            Assert.Equal(80, sizeof(AcxCallbacks));
            Assert.Equal(88, sizeof(AcxStatusInfo));
            Assert.Equal(112, sizeof(AcxEstimateInfo));
        }
    }

    [Fact]
    public void V1FieldOffsetsMatchFrozenLayout()
    {
        Assert.Equal(0, (int)Marshal.OffsetOf<AcxInput>(nameof(AcxInput.StructSize)));
        Assert.Equal(8, (int)Marshal.OffsetOf<AcxInput>(nameof(AcxInput.Kind)));
        Assert.Equal(16, (int)Marshal.OffsetOf<AcxInput>(nameof(AcxInput.Path)));
        Assert.Equal(24, (int)Marshal.OffsetOf<AcxInput>(nameof(AcxInput.Fd)));

        Assert.Equal(8, (int)Marshal.OffsetOf<AcxAttackSpec>(nameof(AcxAttackSpec.Input)));
        Assert.Equal(80, (int)Marshal.OffsetOf<AcxAttackSpec>(nameof(AcxAttackSpec.Mode)));
        Assert.Equal(88, (int)Marshal.OffsetOf<AcxAttackSpec>(nameof(AcxAttackSpec.DictionaryPath)));
        Assert.Equal(128, (int)Marshal.OffsetOf<AcxAttackSpec>(nameof(AcxAttackSpec.Custom0)));
        Assert.Equal(192, (int)Marshal.OffsetOf<AcxAttackSpec>(nameof(AcxAttackSpec.Threads)));
        Assert.Equal(226, (int)Marshal.OffsetOf<AcxAttackSpec>(nameof(AcxAttackSpec.ReportStats)));
    }

    [Fact]
    public void FactoryMethodsSetStructSizeAndVersion()
    {
        unsafe
        {
            Assert.Equal((uint)sizeof(AcxConfig), AcxConfig.Create().StructSize);
            Assert.Equal((uint)sizeof(AcxStatusInfo), AcxStatusInfo.Create().StructSize);
            Assert.Equal((uint)sizeof(AcxEstimateInfo), AcxEstimateInfo.Create().StructSize);
            Assert.Equal(1u, AcxConfig.Create().Version);
            Assert.Equal(1u, AcxStatusInfo.Create().Version);
            Assert.Equal(1u, AcxEstimateInfo.Create().Version);
        }
    }
}
