// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

namespace ArchCracker.Shared;

public static class AcxFormatCode
{
    public const uint Zip = 0;
    public const uint SevenZ = 1;
    public const uint Rar4 = 2;
    public const uint Rar5 = 3;
}

public static class AcxEncryptionCode
{
    public const uint None = 0;
    public const uint ZipCrypto = 1;
    public const uint Aes = 2;
    public const uint Rar = 3;
}
