using PostQuantum.FileFormat.File;
using PostQuantum.FileFormat.Cbor;

namespace PostQuantum.FileFormat.Tests.File;

/// <summary>
/// Phase 2.7: Happy Path Tests
/// Verify that structurally valid files (unsigned and signed) are accepted
/// through all Phase 2 validation stages, reaching Phase 3 (decryption).
/// </summary>
public sealed class HappyPath_ValidationTests
{
    [Fact]
    public void Validates_unsigned_file_with_single_recipient()
    {
        var header = BuildValidUnsignedHeader();
        var file = BuildUnsignedFileWithFooter(header);
        var reader = PqfFileReader.OpenForValidation(file);
        Assert.NotNull(reader);
    }

    [Fact]
    public void Validates_signed_file_with_full_signature_structure()
    {
        var header = BuildValidSignedHeader();
        var file = BuildSignedFileFullStructure(header);
        var reader = PqfFileReader.OpenForValidation(file);
        Assert.NotNull(reader);
    }

    [Fact]
    public void Validates_file_with_multiple_recipients()
    {
        var header = BuildUnsignedHeaderWithMultipleRecipients(2);
        var file = BuildUnsignedFileWithFooter(header);
        var reader = PqfFileReader.OpenForValidation(file);
        Assert.NotNull(reader);
    }

    [Fact]
    public void Validates_file_with_large_chunk_size()
    {
        var header = BuildUnsignedHeaderWithChunkSize(16777216);
        var file = BuildUnsignedFileWithFooter(header);
        var reader = PqfFileReader.OpenForValidation(file);
        Assert.NotNull(reader);
    }

    private static CborValue BuildValidUnsignedHeader()
    {
        var alg = CborValue.Map(new List<KeyValuePair<CborValue, CborValue>>
        {
            new(CborValue.Text("aead"), CborValue.Text("aes-256-gcm-chunked")),
            new(CborValue.Text("combiner"), CborValue.Text("x-wing")),
            new(CborValue.Text("kdf"), CborValue.Text("hkdf-sha256")),
            new(CborValue.Text("kem"), CborValue.Text("x25519+ml-kem-768")),
            new(CborValue.Text("sig"), CborValue.Text("ed25519+ml-dsa-87")),
        });

        var recipient = CborValue.Map(new List<KeyValuePair<CborValue, CborValue>>
        {
            new(CborValue.Text("classical_epk"), CborValue.Bytes(new byte[32])),
            new(CborValue.Text("pqc_ct"), CborValue.Bytes(new byte[1088])),
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
            new(CborValue.Text("combiner"), CborValue.Text("x-wing")),
            new(CborValue.Text("kdf"), CborValue.Text("hkdf-sha256")),
            new(CborValue.Text("kem"), CborValue.Text("x25519+ml-kem-768")),
            new(CborValue.Text("sig"), CborValue.Text("ed25519+ml-dsa-87")),
        });

        var recipient = CborValue.Map(new List<KeyValuePair<CborValue, CborValue>>
        {
            new(CborValue.Text("classical_epk"), CborValue.Bytes(new byte[32])),
            new(CborValue.Text("pqc_ct"), CborValue.Bytes(new byte[1088])),
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

    private static CborValue BuildUnsignedHeaderWithMultipleRecipients(int count)
    {
        var alg = CborValue.Map(new List<KeyValuePair<CborValue, CborValue>>
        {
            new(CborValue.Text("aead"), CborValue.Text("aes-256-gcm-chunked")),
            new(CborValue.Text("combiner"), CborValue.Text("x-wing")),
            new(CborValue.Text("kdf"), CborValue.Text("hkdf-sha256")),
            new(CborValue.Text("kem"), CborValue.Text("x25519+ml-kem-768")),
            new(CborValue.Text("sig"), CborValue.Text("ed25519+ml-dsa-87")),
        });

        var recipients = new CborValue[count];
        for (int i = 0; i < count; i++)
        {
            recipients[i] = CborValue.Map(new List<KeyValuePair<CborValue, CborValue>>
            {
                new(CborValue.Text("classical_epk"), CborValue.Bytes(new byte[32])),
                new(CborValue.Text("pqc_ct"), CborValue.Bytes(new byte[1088])),
                new(CborValue.Text("wrapped_dek"), CborValue.Bytes(new byte[48])),
                new(CborValue.Text("wrapped_dek_nonce"), CborValue.Bytes(new byte[12])),
            });
        }

        return CborValue.Map(new List<KeyValuePair<CborValue, CborValue>>
        {
            new(CborValue.Text("alg"), alg),
            new(CborValue.Text("chunk_size"), CborValue.Uint(65536)),
            new(CborValue.Text("created"), CborValue.Tag(0, CborValue.Text("2026-04-21T14:30:00Z"))),
            new(CborValue.Text("file_id"), CborValue.Bytes(new byte[16])),
            new(CborValue.Text("recipients"), CborValue.Array(recipients)),
        });
    }

    private static CborValue BuildUnsignedHeaderWithChunkSize(uint chunkSize)
    {
        var alg = CborValue.Map(new List<KeyValuePair<CborValue, CborValue>>
        {
            new(CborValue.Text("aead"), CborValue.Text("aes-256-gcm-chunked")),
            new(CborValue.Text("combiner"), CborValue.Text("x-wing")),
            new(CborValue.Text("kdf"), CborValue.Text("hkdf-sha256")),
            new(CborValue.Text("kem"), CborValue.Text("x25519+ml-kem-768")),
            new(CborValue.Text("sig"), CborValue.Text("ed25519+ml-dsa-87")),
        });

        var recipient = CborValue.Map(new List<KeyValuePair<CborValue, CborValue>>
        {
            new(CborValue.Text("classical_epk"), CborValue.Bytes(new byte[32])),
            new(CborValue.Text("pqc_ct"), CborValue.Bytes(new byte[1088])),
            new(CborValue.Text("wrapped_dek"), CborValue.Bytes(new byte[48])),
            new(CborValue.Text("wrapped_dek_nonce"), CborValue.Bytes(new byte[12])),
        });

        return CborValue.Map(new List<KeyValuePair<CborValue, CborValue>>
        {
            new(CborValue.Text("alg"), alg),
            new(CborValue.Text("chunk_size"), CborValue.Uint(chunkSize)),
            new(CborValue.Text("created"), CborValue.Tag(0, CborValue.Text("2026-04-21T14:30:00Z"))),
            new(CborValue.Text("file_id"), CborValue.Bytes(new byte[16])),
            new(CborValue.Text("recipients"), CborValue.Array(new[] { recipient })),
        });
    }

    private static byte[] BuildUnsignedFileWithFooter(CborValue header)
    {
        var encodedHeader = DeterministicCborEncoder.Encode(header);
        var buffer = new byte[10 + encodedHeader.Length + 20];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(buffer, 0x50514631);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(4), 0x0001);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(6), (uint)encodedHeader.Length);
        encodedHeader.CopyTo(buffer.AsMemory(10));
        var footerOffset = 10 + encodedHeader.Length;
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(footerOffset), 0x50514645);
        System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(buffer.AsSpan(footerOffset + 4), 0);
        System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(buffer.AsSpan(footerOffset + 12), 0);
        return buffer;
    }

    private static byte[] BuildSignedFileFullStructure(CborValue header)
    {
        var encodedHeader = DeterministicCborEncoder.Encode(header);
        var buffer = new byte[10 + encodedHeader.Length + 4691 + 20 + 4691];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(buffer, 0x50514631);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(4), 0x0001);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(6), (uint)encodedHeader.Length);
        encodedHeader.CopyTo(buffer.AsMemory(10));
        var footerOffset = 10 + encodedHeader.Length + 4691;
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(footerOffset), 0x50514645);
        System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(buffer.AsSpan(footerOffset +4), 0);
        System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(buffer.AsSpan(footerOffset + 12), 0);
        return buffer;
    }
}
