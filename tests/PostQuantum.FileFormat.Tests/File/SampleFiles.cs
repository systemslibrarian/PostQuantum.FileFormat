using System.Buffers.Binary;

namespace PostQuantum.FileFormat.Tests.File;

/// <summary>
/// Byte-level PQF file builders for testing. Produces both valid and malformed
/// files with controlled structural properties.
/// </summary>
public static class SampleFiles
{
    private const string PqfMagic = "PQF1";
    private const ushort PqfVersion = 0x0001;

    /// <summary>
    /// Build a malformed file with wrong magic: "XXXX" instead of "PQF1".
    /// </summary>
    public static byte[] BuildMalformed_WrongMagic()
    {
        var bytes = new byte[256];
        "XXXX"u8.CopyTo(bytes);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), PqfVersion);
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(6), 10);
        return bytes;
    }

    /// <summary>
    /// Build a malformed file with wrong version: 0x0002 instead of 0x0001.
    /// </summary>
    public static byte[] BuildMalformed_WrongVersion()
    {
        var bytes = new byte[256];
        "PQF1"u8.CopyTo(bytes);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), 0x0002);
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(6), 10);
        return bytes;
    }

    /// <summary>
    /// Build a malformed file with header length exceeding 1 MiB.
    /// </summary>
    public static byte[] BuildMalformed_HeaderLengthTooLarge()
    {
        var bytes = new byte[10];
        "PQF1"u8.CopyTo(bytes);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), PqfVersion);
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(6), 2_000_000); // 2 MiB
        return bytes;
    }

    /// <summary>
    /// Build a malformed file with header length = 0.
    /// </summary>
    public static byte[] BuildMalformed_HeaderLengthZero()
    {
        var bytes = new byte[10];
        "PQF1"u8.CopyTo(bytes);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), PqfVersion);
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(6), 0);
        return bytes;
    }

    /// <summary>
    /// Build a truncated file: stops before the header is fully present.
    /// </summary>
    public static byte[] BuildMalformed_Truncated_BeforeHeader()
    {
        var bytes = new byte[8]; // Only magic + version, no header length field
        "PQF1"u8.CopyTo(bytes);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), PqfVersion);
        return bytes;
    }
}
