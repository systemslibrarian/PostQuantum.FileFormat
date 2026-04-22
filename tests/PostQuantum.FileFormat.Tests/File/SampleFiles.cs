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

    /// <summary>
    /// Build a malformed file with non-shortest integer encoding in CBOR header.
    /// Maps 0 to 0x18 0x00 (non-shortest form).
    /// </summary>
    public static byte[] BuildMalformed_NonShortestIntegerInHeader()
    {
        // Create a minimal but malformed CBOR map: a1 = 1-item map
        // Key: 0x18 0x00 = non-shortest encoding of 0
        // Value: f4 = false
        var headerCbor = new byte[] { 0xa1, 0x18, 0x00, 0xf4 };
        return WrapCborHeader(headerCbor);
    }

    /// <summary>
    /// Build a malformed file with indefinite-length map in CBOR header.
    /// bf = indefinite-length map start
    /// </summary>
    public static byte[] BuildMalformed_IndefiniteLengthMapInHeader()
    {
        // bf = indefinite-length map; ff = break
        var headerCbor = new byte[] { 0xbf, 0xff };
        return WrapCborHeader(headerCbor);
    }

    /// <summary>
    /// Build a malformed file with out-of-order map keys in CBOR header.
    /// Must have keys encoded but in wrong order (longer first, then shorter).
    /// </summary>
    public static byte[] BuildMalformed_OutOfOrderMapKeysInHeader()
    {
        // a2 = 2-item map
        // Key 1: 0x61 0x62 = text string "b"
        // Value 1: f4 = false
        // Key 2: 0x61 0x61 = text string "a"
        // Value 2: f4 = false
        var headerCbor = new byte[] { 0xa2, 0x61, 0x62, 0xf4, 0x61, 0x61, 0xf4 };
        return WrapCborHeader(headerCbor);
    }

    /// <summary>
    /// Build a malformed file with duplicate keys in CBOR header.
    /// </summary>
    public static byte[] BuildMalformed_DuplicateKeysInHeader()
    {
        // a2 = 2-item map (but we'll insert 2 of the same key)
        // Key 1: 0x61 0x61 = text "a"
        // Value 1: f4 = false
        // Key 2: 0x61 0x61 = text "a" (duplicate)
        // Value 2: f5 = true
        var headerCbor = new byte[] { 0xa2, 0x61, 0x61, 0xf4, 0x61, 0x61, 0xf5 };
        return WrapCborHeader(headerCbor);
    }

    /// <summary>
    /// Build a malformed file with floating-point in CBOR header.
    /// fa = 4-byte float, fb = 8-byte float
    /// </summary>
    public static byte[] BuildMalformed_FloatInHeader()
    {
        // a1 = 1-item map
        // Key: 0x61 0x61 = text "a"
        // Value: fa 3f 80 00 00 = float32(1.0)
        var headerCbor = new byte[] { 0xa1, 0x61, 0x61, 0xfa, 0x3f, 0x80, 0x00, 0x00 };
        return WrapCborHeader(headerCbor);
    }

    /// <summary>
    /// Build a malformed file with trailing bytes after CBOR header.
    /// </summary>
    public static byte[] BuildMalformed_TrailingBytesAfterHeader()
    {
        // Minimal valid CBOR: f4 = false
        var headerCbor = new byte[] { 0xf4, 0xf5 }; // false, true (trailing)
        return WrapCborHeader(headerCbor);
    }

    /// <summary>
    /// Wrap raw CBOR bytes in PQF file header container (magic, version, length, then CBOR).
    /// </summary>
    private static byte[] WrapCborHeader(byte[] cborBytes)
    {
        var buffer = new byte[10 + cborBytes.Length];
        "PQF1"u8.CopyTo(buffer);
        BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(4), PqfVersion);
        BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(6), (uint)cborBytes.Length);
        cborBytes.CopyTo(buffer.AsSpan(10));
        return buffer;
    }
}
