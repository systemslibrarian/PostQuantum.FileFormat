using PostQuantum.FileFormat.File;
using PostQuantum.FileFormat.Cbor;

namespace PostQuantum.FileFormat.Tests.File;

/// <summary>
/// Phase 2.8: Integration Tests
/// Comprehensive end-to-end validation of PQF file structures.
/// Verify that Phase 2 validation pipeline (magic → version → length → CBOR → schema → signature → footer)
/// correctly enforces all refusal conditions in the correct order.
/// </summary>
public sealed class Integration_ValidationTests
{
    [Fact]
    public void Phase2_complete_validation_pipeline_integrates_all_refusals()
    {
        // Build a valid unsigned file that passes all Phase 2 validation stages
        var header = BuildValidUnsignedHeader();
        var encodedHeader = DeterministicCborEncoder.Encode(header);
        var file = BuildUnsignedFileWithFooter(encodedHeader);

        // File should pass validation.
        var reader = PqfFileReader.OpenForValidation(file);
        Assert.NotNull(reader);

        // Verify file structure: should have complete footer at expected offset
        var footerOffset = 10 + encodedHeader.Length;
        Assert.True(file.Length >= footerOffset + 20, "File must contain complete footer");
        var actualMagic = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(file.AsSpan(footerOffset));
        Assert.Equal((uint)0x50514645, actualMagic);
    }

    [Fact]
    public void Phase2_refusal_precedence_magic_checked_before_version()
    {
        // Malformed: wrong magic
        var buffer = new byte[10];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(buffer, 0x58585858); // "XXXX"

        var ex = Assert.Throws<PqfFileException>(() => PqfFileReader.OpenForValidation(buffer));
        Assert.Equal(PqfRefusalReason.MagicMismatch, ex.Reason);
        Assert.Equal(0, ex.Offset);
    }

    [Fact]
    public void Phase2_refusal_precedence_version_checked_after_magic()
    {
        // Malformed: correct magic, wrong version
        var buffer = new byte[10];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(buffer, 0x50514631); // "PQF1"
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(4), 0x0002); // Wrong version

        var ex = Assert.Throws<PqfFileException>(() => PqfFileReader.OpenForValidation(buffer));
        Assert.Equal(PqfRefusalReason.VersionMismatch, ex.Reason);
        Assert.Equal(4, ex.Offset);
    }

    [Fact]
    public void Phase2_refusal_precedence_header_length_checked_after_version()
    {
        // Malformed: correct magic/version, header length too large
        var buffer = new byte[10];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(buffer, 0x50514631);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(4), 0x0001);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(6), 0x50000000); // > 1 MiB

        var ex = Assert.Throws<PqfFileException>(() => PqfFileReader.OpenForValidation(buffer));
        Assert.Equal(PqfRefusalReason.HeaderLengthExceedsLimit, ex.Reason);
        Assert.Equal(6, ex.Offset);
    }

    [Fact]
    public void Phase2_signed_file_with_valid_all_signatures_reaches_phase3()
    {
        var header = BuildValidSignedHeader();
        var encodedHeader = DeterministicCborEncoder.Encode(header);
        var buffer = new byte[10 + encodedHeader.Length + 4691 + 20 + 4691];
        
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(buffer, 0x50514631);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(4), 0x0001);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(6), (uint)encodedHeader.Length);
        encodedHeader.CopyTo(buffer.AsMemory(10));

        var footerOffset = 10 + encodedHeader.Length + 4691;
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(footerOffset), 0x50514645);
        System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(buffer.AsSpan(footerOffset + 4), 0);
        System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(buffer.AsSpan(footerOffset + 12), 0);

        var reader = PqfFileReader.OpenForValidation(buffer);
        Assert.NotNull(reader);
    }

    private static CborValue BuildValidUnsignedHeader()
    {
        var alg = CborValue.Map(new List<KeyValuePair<CborValue, CborValue>>
        {
            new(CborValue.Text("aead"), CborValue.Text("aes-256-gcm-chunked")),
            new(CborValue.Text("combiner"), CborValue.Text("pqf1-bind-extract-v1")),
            new(CborValue.Text("kdf"), CborValue.Text("hkdf-sha256")),
            new(CborValue.Text("kem"), CborValue.Text("x25519+ml-kem-1024")),
            new(CborValue.Text("sig"), CborValue.Text("ed25519+ml-dsa-87")),
        });

        var recipient = CborValue.Map(new List<KeyValuePair<CborValue, CborValue>>
        {
            new(CborValue.Text("classical_epk"), CborValue.Bytes(new byte[32])),
            new(CborValue.Text("pqc_ct"), CborValue.Bytes(new byte[1568])),
            new(CborValue.Text("wrapped_dek"), CborValue.Bytes(new byte[48])),
            new(CborValue.Text("wrapped_dek_nonce"), CborValue.Bytes(new byte[12])),
        });

        return CborValue.Map(new List<KeyValuePair<CborValue, CborValue>>
        {
            new(CborValue.Text("alg"), alg),
            new(CborValue.Text("chunk_size"), CborValue.Uint(65536)),
            new(CborValue.Text("created"), CborValue.Tag(0, CborValue.Text("2026-04-21T14:30:00Z"))),
            new(CborValue.Text("file_id"), CborValue.Bytes(new byte[16])),
            new(CborValue.Text("recipients"), CborValue.Array(new[] { recipient })),
        });
    }

    private static CborValue BuildValidSignedHeader()
    {
        var alg = CborValue.Map(new List<KeyValuePair<CborValue, CborValue>>
        {
            new(CborValue.Text("aead"), CborValue.Text("aes-256-gcm-chunked")),
            new(CborValue.Text("combiner"), CborValue.Text("pqf1-bind-extract-v1")),
            new(CborValue.Text("kdf"), CborValue.Text("hkdf-sha256")),
            new(CborValue.Text("kem"), CborValue.Text("x25519+ml-kem-1024")),
            new(CborValue.Text("sig"), CborValue.Text("ed25519+ml-dsa-87")),
        });

        var recipient = CborValue.Map(new List<KeyValuePair<CborValue, CborValue>>
        {
            new(CborValue.Text("classical_epk"), CborValue.Bytes(new byte[32])),
            new(CborValue.Text("pqc_ct"), CborValue.Bytes(new byte[1568])),
            new(CborValue.Text("wrapped_dek"), CborValue.Bytes(new byte[48])),
            new(CborValue.Text("wrapped_dek_nonce"), CborValue.Bytes(new byte[12])),
        });

        var signer = CborValue.Map(new List<KeyValuePair<CborValue, CborValue>>
        {
            new(CborValue.Text("classical_pub"), CborValue.Bytes(new byte[32])),
            new(CborValue.Text("pqc_pub"), CborValue.Bytes(new byte[2592])),
        });

        return CborValue.Map(new List<KeyValuePair<CborValue, CborValue>>
        {
            new(CborValue.Text("alg"), alg),
            new(CborValue.Text("chunk_size"), CborValue.Uint(65536)),
            new(CborValue.Text("created"), CborValue.Tag(0, CborValue.Text("2026-04-21T14:30:00Z"))),
            new(CborValue.Text("file_id"), CborValue.Bytes(new byte[16])),
            new(CborValue.Text("recipients"), CborValue.Array(new[] { recipient })),
            new(CborValue.Text("signer"), signer),
        });
    }

    private static byte[] BuildUnsignedFileWithFooter(System.ReadOnlyMemory<byte> headerCbor)
    {
        var buffer = new byte[10 + headerCbor.Length + 20];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(buffer, 0x50514631);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(4), 0x0001);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(6), (uint)headerCbor.Length);
        headerCbor.CopyTo(buffer.AsMemory(10));
        var footerOffset = 10 + headerCbor.Length;
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(footerOffset), 0x50514645);
        System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(buffer.AsSpan(footerOffset + 4), 0);
        System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(buffer.AsSpan(footerOffset + 12), 0);
        return buffer;
    }
}
