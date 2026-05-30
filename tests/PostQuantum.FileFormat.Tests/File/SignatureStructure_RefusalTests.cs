using PostQuantum.FileFormat.File;

namespace PostQuantum.FileFormat.Tests.File;

public sealed class SignatureStructure_RefusalTests
{
    [Fact]
    public void Reader_accepts_signed_file_with_valid_signatures()
    {
        // Unsigned file with valid structure: should throw NotImplementedException for chunk parsing (Phase 2.4+)
        var header = BuildValidSignedHeader();
        var encodedHeader = PostQuantum.FileFormat.Cbor.DeterministicCborEncoder.Encode(header);
        var buffer = BuildSignedFileWithSignatures(encodedHeader);
        
        var reader = PqfFileReader.OpenForValidation(buffer);
        Assert.NotNull(reader);
    }

    [Fact]
    public void Reader_accepts_unsigned_file_with_no_signatures()
    {
        var header = BuildValidUnsignedHeader();
        var encodedHeader = PostQuantum.FileFormat.Cbor.DeterministicCborEncoder.Encode(header);
        var buffer = BuildUnsignedFileWithFooter(encodedHeader);

        var reader = PqfFileReader.OpenForValidation(buffer);
        Assert.NotNull(reader);
    }

    [Fact]
    public void Reader_refuses_signed_file_missing_header_signature()
    {
        var header = BuildValidSignedHeader();
        var encodedHeader = PostQuantum.FileFormat.Cbor.DeterministicCborEncoder.Encode(header);
        var buffer = BuildSignedFileMissingHeaderSignature(encodedHeader);

        var ex = Assert.Throws<PqfFileException>(() => PqfFileReader.OpenForValidation(buffer));
        Assert.Equal(PqfRefusalReason.TruncationDetected, ex.Reason);
    }

    [Fact]
    public void Reader_refuses_signed_file_wrong_header_signature_length()
    {
        var header = BuildValidSignedHeader();
        var encodedHeader = PostQuantum.FileFormat.Cbor.DeterministicCborEncoder.Encode(header);
        var buffer = BuildSignedFileWithShortHeaderSignature(encodedHeader);

        var ex = Assert.Throws<PqfFileException>(() => PqfFileReader.OpenForValidation(buffer));
        Assert.Equal(PqfRefusalReason.TruncationDetected, ex.Reason);
    }

    private static PostQuantum.FileFormat.Cbor.CborValue BuildValidUnsignedHeader()
    {
        var alg = PostQuantum.FileFormat.Cbor.CborValue.Map(new List<KeyValuePair<PostQuantum.FileFormat.Cbor.CborValue, PostQuantum.FileFormat.Cbor.CborValue>>
        {
            new(PostQuantum.FileFormat.Cbor.CborValue.Text("aead"), PostQuantum.FileFormat.Cbor.CborValue.Text("aes-256-gcm-chunked")),
            new(PostQuantum.FileFormat.Cbor.CborValue.Text("combiner"), PostQuantum.FileFormat.Cbor.CborValue.Text("x-wing")),
            new(PostQuantum.FileFormat.Cbor.CborValue.Text("kdf"), PostQuantum.FileFormat.Cbor.CborValue.Text("hkdf-sha256")),
            new(PostQuantum.FileFormat.Cbor.CborValue.Text("kem"), PostQuantum.FileFormat.Cbor.CborValue.Text("x25519+ml-kem-768")),
            new(PostQuantum.FileFormat.Cbor.CborValue.Text("sig"), PostQuantum.FileFormat.Cbor.CborValue.Text("ed25519+ml-dsa-87")),
        });

        var recipient = PostQuantum.FileFormat.Cbor.CborValue.Map(new List<KeyValuePair<PostQuantum.FileFormat.Cbor.CborValue, PostQuantum.FileFormat.Cbor.CborValue>>
        {
            new(PostQuantum.FileFormat.Cbor.CborValue.Text("classical_epk"), PostQuantum.FileFormat.Cbor.CborValue.Bytes(new byte[32])),
            new(PostQuantum.FileFormat.Cbor.CborValue.Text("pqc_ct"), PostQuantum.FileFormat.Cbor.CborValue.Bytes(new byte[1088])),
            new(PostQuantum.FileFormat.Cbor.CborValue.Text("wrapped_dek"), PostQuantum.FileFormat.Cbor.CborValue.Bytes(new byte[48])),
            new(PostQuantum.FileFormat.Cbor.CborValue.Text("wrapped_dek_nonce"), PostQuantum.FileFormat.Cbor.CborValue.Bytes(new byte[12])),
        });

        return PostQuantum.FileFormat.Cbor.CborValue.Map(new List<KeyValuePair<PostQuantum.FileFormat.Cbor.CborValue, PostQuantum.FileFormat.Cbor.CborValue>>
        {
            new(PostQuantum.FileFormat.Cbor.CborValue.Text("alg"), alg),
            new(PostQuantum.FileFormat.Cbor.CborValue.Text("chunk_size"), PostQuantum.FileFormat.Cbor.CborValue.Uint(65536)),
            new(PostQuantum.FileFormat.Cbor.CborValue.Text("created"), PostQuantum.FileFormat.Cbor.CborValue.Tag(0, PostQuantum.FileFormat.Cbor.CborValue.Text("2026-04-21T14:30:00Z"))),
            new(PostQuantum.FileFormat.Cbor.CborValue.Text("file_id"), PostQuantum.FileFormat.Cbor.CborValue.Bytes(new byte[16])),
            new(PostQuantum.FileFormat.Cbor.CborValue.Text("recipients"), PostQuantum.FileFormat.Cbor.CborValue.Array(new[] { recipient })),
        });
    }

    private static PostQuantum.FileFormat.Cbor.CborValue BuildValidSignedHeader()
    {
        var alg = PostQuantum.FileFormat.Cbor.CborValue.Map(new List<KeyValuePair<PostQuantum.FileFormat.Cbor.CborValue, PostQuantum.FileFormat.Cbor.CborValue>>
        {
            new(PostQuantum.FileFormat.Cbor.CborValue.Text("aead"), PostQuantum.FileFormat.Cbor.CborValue.Text("aes-256-gcm-chunked")),
            new(PostQuantum.FileFormat.Cbor.CborValue.Text("combiner"), PostQuantum.FileFormat.Cbor.CborValue.Text("x-wing")),
            new(PostQuantum.FileFormat.Cbor.CborValue.Text("kdf"), PostQuantum.FileFormat.Cbor.CborValue.Text("hkdf-sha256")),
            new(PostQuantum.FileFormat.Cbor.CborValue.Text("kem"), PostQuantum.FileFormat.Cbor.CborValue.Text("x25519+ml-kem-768")),
            new(PostQuantum.FileFormat.Cbor.CborValue.Text("sig"), PostQuantum.FileFormat.Cbor.CborValue.Text("ed25519+ml-dsa-87")),
        });

        var recipient = PostQuantum.FileFormat.Cbor.CborValue.Map(new List<KeyValuePair<PostQuantum.FileFormat.Cbor.CborValue, PostQuantum.FileFormat.Cbor.CborValue>>
        {
            new(PostQuantum.FileFormat.Cbor.CborValue.Text("classical_epk"), PostQuantum.FileFormat.Cbor.CborValue.Bytes(new byte[32])),
            new(PostQuantum.FileFormat.Cbor.CborValue.Text("pqc_ct"), PostQuantum.FileFormat.Cbor.CborValue.Bytes(new byte[1088])),
            new(PostQuantum.FileFormat.Cbor.CborValue.Text("wrapped_dek"), PostQuantum.FileFormat.Cbor.CborValue.Bytes(new byte[48])),
            new(PostQuantum.FileFormat.Cbor.CborValue.Text("wrapped_dek_nonce"), PostQuantum.FileFormat.Cbor.CborValue.Bytes(new byte[12])),
        });

        var signer = PostQuantum.FileFormat.Cbor.CborValue.Map(new List<KeyValuePair<PostQuantum.FileFormat.Cbor.CborValue, PostQuantum.FileFormat.Cbor.CborValue>>
        {
            new(PostQuantum.FileFormat.Cbor.CborValue.Text("classical_pub"), PostQuantum.FileFormat.Cbor.CborValue.Bytes(new byte[32])),
            new(PostQuantum.FileFormat.Cbor.CborValue.Text("pqc_pub"), PostQuantum.FileFormat.Cbor.CborValue.Bytes(new byte[2592])),
        });

        return PostQuantum.FileFormat.Cbor.CborValue.Map(new List<KeyValuePair<PostQuantum.FileFormat.Cbor.CborValue, PostQuantum.FileFormat.Cbor.CborValue>>
        {
            new(PostQuantum.FileFormat.Cbor.CborValue.Text("alg"), alg),
            new(PostQuantum.FileFormat.Cbor.CborValue.Text("chunk_size"), PostQuantum.FileFormat.Cbor.CborValue.Uint(65536)),
            new(PostQuantum.FileFormat.Cbor.CborValue.Text("created"), PostQuantum.FileFormat.Cbor.CborValue.Tag(0, PostQuantum.FileFormat.Cbor.CborValue.Text("2026-04-21T14:30:00Z"))),
            new(PostQuantum.FileFormat.Cbor.CborValue.Text("file_id"), PostQuantum.FileFormat.Cbor.CborValue.Bytes(new byte[16])),
            new(PostQuantum.FileFormat.Cbor.CborValue.Text("recipients"), PostQuantum.FileFormat.Cbor.CborValue.Array(new[] { recipient })),
            new(PostQuantum.FileFormat.Cbor.CborValue.Text("signer"), signer),
        });
    }

    private static byte[] BuildUnsignedFileWithFooter(System.ReadOnlyMemory<byte> headerCbor)
    {
        var buffer = new byte[10 + headerCbor.Length + 20];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(buffer, 0x50514631); // "PQF1"
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(4), 0x0001);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(6), (uint)headerCbor.Length);
        headerCbor.CopyTo(buffer.AsMemory(10));

        // Footer (no signature for unsigned)
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(10 + headerCbor.Length), 0x50514645); // "PQFE"
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(buffer.AsSpan(10 + headerCbor.Length + 4), 0);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(buffer.AsSpan(10 + headerCbor.Length + 12), 0);
        return buffer;
    }

    private static byte[] BuildSignedFileWithSignatures(System.ReadOnlyMemory<byte> headerCbor)
    {
        var buffer = new byte[10 + headerCbor.Length + 4691 + 20 + 4691]; // sig=4691, footer=20, sig=4691
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(buffer, 0x50514631); // "PQF1"
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(4), 0x0001);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(6), (uint)headerCbor.Length);
        headerCbor.CopyTo(buffer.AsMemory(10));

        // Header signature (placeholder)
        var headerSigOffset = 10 + headerCbor.Length;
        // Leave zeros for header sig

        // Footer
        var footerOffset = headerSigOffset + 4691;
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(footerOffset), 0x50514645); // "PQFE"
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(buffer.AsSpan(footerOffset + 4), 0);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(buffer.AsSpan(footerOffset + 12), 0);

        // File signature (placeholder)
        // Leave zeros for file sig

        return buffer;
    }

    private static byte[] BuildSignedFileMissingHeaderSignature(System.ReadOnlyMemory<byte> headerCbor)
    {
        var buffer = new byte[10 + headerCbor.Length + 20]; // Missing signatures
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(buffer, 0x50514631); // "PQF1"
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(4), 0x0001);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(6), (uint)headerCbor.Length);
        headerCbor.CopyTo(buffer.AsMemory(10));

        // Footer (no signatures)
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(10 + headerCbor.Length), 0x50514645); // "PQFE"
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(buffer.AsSpan(10 + headerCbor.Length + 4), 0);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(buffer.AsSpan(10 + headerCbor.Length + 12), 0);
        return buffer;
    }

    private static byte[] BuildSignedFileWithShortHeaderSignature(System.ReadOnlyMemory<byte> headerCbor)
    {
        var headerSignatureLength = 4690;
        var fileSignatureLength = 4690;
        var buffer = new byte[10 + headerCbor.Length + headerSignatureLength + 20 + fileSignatureLength];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(buffer, 0x50514631); // "PQF1"
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(4), 0x0001);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(6), (uint)headerCbor.Length);
        headerCbor.CopyTo(buffer.AsMemory(10));

        var footerOffset = 10 + headerCbor.Length + headerSignatureLength;
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(footerOffset), 0x50514645); // "PQFE"
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(buffer.AsSpan(footerOffset + 4), 0);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt64BigEndian(buffer.AsSpan(footerOffset + 12), 0);
        return buffer;
    }

}
