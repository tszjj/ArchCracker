// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors

using System.IO.Compression;
using System.Text;

namespace ArchCracker.Shared.Testing;

/// <summary>
/// Deterministic ZipCrypto/Stored fixture writer for desktop smoke and tests.
/// It writes no plaintext password or dictionary into the repository.
/// </summary>
public static class ZipCryptoFixture
{
    public static void WritePlain(string path, string entryName, string plaintext)
    {
        using var stream = File.Create(path);
        using var archive = new ZipArchive(stream, ZipArchiveMode.Create, leaveOpen: false);
        var entry = archive.CreateEntry(entryName, CompressionLevel.NoCompression);
        using var writer = new StreamWriter(entry.Open(), new UTF8Encoding(false));
        writer.Write(plaintext);
    }

    public static void Write(string path, string password, string entryName, string plaintext)
    {
        var name = Encoding.UTF8.GetBytes(entryName);
        var data = Encoding.UTF8.GetBytes(plaintext);
        var crc = Crc32(data);
        var encrypted = Encrypt(data, password, crc);
        var localHeaderSize = 30u + (uint)name.Length;
        var centralOffset = localHeaderSize + (uint)encrypted.Length + 16u;
        var centralSize = 46u + (uint)name.Length;

        using var stream = File.Create(path);
        using var writer = new BinaryWriter(stream);

        writer.Write(0x04034b50u);
        writer.Write((ushort)20);
        writer.Write((ushort)9); // ZipCrypto + data descriptor
        writer.Write((ushort)0); // stored
        writer.Write((ushort)0); // time
        writer.Write((ushort)0x21); // date 1980-01-01
        writer.Write(0u);
        writer.Write(0u);
        writer.Write(0u);
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
        writer.Write((ushort)0);
        writer.Write((ushort)0x21);
        writer.Write(crc);
        writer.Write((uint)encrypted.Length);
        writer.Write((uint)data.Length);
        writer.Write((ushort)name.Length);
        writer.Write((ushort)0);
        writer.Write((ushort)0);
        writer.Write((ushort)0);
        writer.Write((ushort)0);
        writer.Write(0u);
        writer.Write(0u);
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

    private static byte[] Encrypt(byte[] data, string password, uint crc)
    {
        uint key0 = 0x12345678, key1 = 0x23456789, key2 = 0x34567890;
        foreach (var value in Encoding.ASCII.GetBytes(password)) UpdateKey(value);

        var result = new byte[12 + data.Length];
        for (var index = 0; index < 11; index++) result[index] = EncryptByte((byte)index);
        result[11] = EncryptByte(0); // MS-DOS time high byte with bit 3 set
        for (var index = 0; index < data.Length; index++) result[12 + index] = EncryptByte(data[index]);
        return result;

        byte EncryptByte(byte plaintext)
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
        foreach (var value in data) crc = Crc32Step(crc, value);
        return crc ^ 0xffffffffu;
    }

    private static uint Crc32Step(uint crc, byte value)
    {
        crc ^= value;
        for (var bit = 0; bit < 8; bit++)
            crc = (crc & 1) != 0 ? (crc >> 1) ^ 0xedb88320u : crc >> 1;
        return crc;
    }
}
