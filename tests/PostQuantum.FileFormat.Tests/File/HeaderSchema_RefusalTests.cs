using PostQuantum.FileFormat.File;
using PostQuantum.FileFormat.Cbor;

namespace PostQuantum.FileFormat.Tests.File;

public sealed class HeaderSchema_RefusalTests
{
    [Fact]
    public void Reader_refuses_missing_alg_field()
    {
        // Build header without "alg" field
        var header = new CborValue.MapValue(new List<KeyValuePair<CborValue, CborValue>>
        {
            new(CborValue.Text("chunk_size"), CborValue.Uint(65536)),
            new(CborValue.Text("created"), CborValue.Tag(0, CborValue.Text("2026-04-21T14:30:00Z"))),
            new(CborValue.Text("file_id"), CborValue.Bytes(new byte[16])),
            new(CborValue.Text("recipients"), CborValue.Array(new[]
            {
                new CborValue.MapValue(new List<KeyValuePair<CborValue, CborValue>>
                {
                    new(CborValue.Text("classical_epk"), CborValue.Bytes(new byte[32])),
                    new(CborValue.Text("pqc_ct"), CborValue.Bytes(new byte[1088])),
                    new(CborValue.Text("wrapped_dek"), CborValue.Bytes(new byte[48])),
                    new(CborValue.Text("wrapped_dek_nonce"), CborValue.Bytes(new byte[12])),
                })
            }))
        });

        var bytes = BuildFileWithHeader(header);
        var ex = Assert.Throws<PqfFileException>(() => PqfFileReader.OpenForValidation(bytes));
        Assert.Equal(PqfRefusalReason.MissingRequiredField, ex.Reason);
    }

    [Fact]
    public void Reader_refuses_unknown_header_field()
    {
        var header = BuildValidHeaderCbor();
        var entries = ((CborValue.MapValue)header).Entries.ToList();
        entries.Add(new(CborValue.Text("unknown_field"), CborValue.Text("value")));
        var headerWithUnknown = CborValue.Map(entries);

        var bytes = BuildFileWithHeader(headerWithUnknown);
        var ex = Assert.Throws<PqfFileException>(() => PqfFileReader.OpenForValidation(bytes));
        Assert.Equal(PqfRefusalReason.UnknownHeaderField, ex.Reason);
    }

    [Fact]
    public void Reader_refuses_wrong_chunk_size_value()
    {
        var header = BuildValidHeaderCbor();
        var entries = ((CborValue.MapValue)header).Entries.ToList();
        // Replace chunk_size with invalid value (not power of 2)
        entries = entries.Where(x => ((CborValue.TextValue)x.Key).Value != "chunk_size").ToList();
        entries.Add(new(CborValue.Text("chunk_size"), CborValue.Uint(65535))); // Not power of 2
        var headerModified = CborValue.Map(entries);

        var bytes = BuildFileWithHeader(headerModified);
        var ex = Assert.Throws<PqfFileException>(() => PqfFileReader.OpenForValidation(bytes));
        Assert.Equal(PqfRefusalReason.ChunkSizeInvalid, ex.Reason);
    }

    [Fact]
    public void Reader_refuses_chunk_size_too_small()
    {
        var header = BuildValidHeaderCbor();
        var entries = ((CborValue.MapValue)header).Entries.ToList();
        entries = entries.Where(x => ((CborValue.TextValue)x.Key).Value != "chunk_size").ToList();
        entries.Add(new(CborValue.Text("chunk_size"), CborValue.Uint(2048))); // Too small
        var headerModified = CborValue.Map(entries);

        var bytes = BuildFileWithHeader(headerModified);
        var ex = Assert.Throws<PqfFileException>(() => PqfFileReader.OpenForValidation(bytes));
        Assert.Equal(PqfRefusalReason.ChunkSizeInvalid, ex.Reason);
    }

    [Fact]
    public void Reader_refuses_created_without_utc_z_suffix()
    {
        var header = BuildValidHeaderCbor();
        var entries = ((CborValue.MapValue)header).Entries.ToList();
        entries = entries.Where(x => ((CborValue.TextValue)x.Key).Value != "created").ToList();
        entries.Add(new(CborValue.Text("created"), CborValue.Tag(0, CborValue.Text("2026-04-21T14:30:00+05:00")))); // With offset
        var headerModified = CborValue.Map(entries);

        var bytes = BuildFileWithHeader(headerModified);
        var ex = Assert.Throws<PqfFileException>(() => PqfFileReader.OpenForValidation(bytes));
        Assert.Equal(PqfRefusalReason.CreatedTimestampInvalid, ex.Reason);
    }

    [Fact]
    public void Reader_refuses_file_id_wrong_length()
    {
        var header = BuildValidHeaderCbor();
        var entries = ((CborValue.MapValue)header).Entries.ToList();
        entries = entries.Where(x => ((CborValue.TextValue)x.Key).Value != "file_id").ToList();
        entries.Add(new(CborValue.Text("file_id"), CborValue.Bytes(new byte[8]))); // Wrong length
        var headerModified = CborValue.Map(entries);

        var bytes = BuildFileWithHeader(headerModified);
        var ex = Assert.Throws<PqfFileException>(() => PqfFileReader.OpenForValidation(bytes));
        Assert.Equal(PqfRefusalReason.BinaryFieldLengthMismatch, ex.Reason);
    }

    [Fact]
    public void Reader_refuses_empty_recipients_array()
    {
        var header = BuildValidHeaderCbor();
        var entries = ((CborValue.MapValue)header).Entries.ToList();
        entries = entries.Where(x => ((CborValue.TextValue)x.Key).Value != "recipients").ToList();
        entries.Add(new(CborValue.Text("recipients"), CborValue.Array(new CborValue[0]))); // Empty
        var headerModified = CborValue.Map(entries);

        var bytes = BuildFileWithHeader(headerModified);
        var ex = Assert.Throws<PqfFileException>(() => PqfFileReader.OpenForValidation(bytes));
        Assert.Equal(PqfRefusalReason.RecipientsEmpty, ex.Reason);
    }

    [Fact]
    public void Reader_refuses_recipient_classical_epk_wrong_length()
    {
        var recipient = new CborValue.MapValue(new List<KeyValuePair<CborValue, CborValue>>
        {
            new(CborValue.Text("classical_epk"), CborValue.Bytes(new byte[16])), // Wrong: 16 instead of 32
            new(CborValue.Text("pqc_ct"), CborValue.Bytes(new byte[1088])),
            new(CborValue.Text("wrapped_dek"), CborValue.Bytes(new byte[48])),
            new(CborValue.Text("wrapped_dek_nonce"), CborValue.Bytes(new byte[12])),
        });

        var header = BuildValidHeaderCbor();
        var entries = ((CborValue.MapValue)header).Entries.ToList();
        entries = entries.Where(x => ((CborValue.TextValue)x.Key).Value != "recipients").ToList();
        entries.Add(new(CborValue.Text("recipients"), CborValue.Array(new[] { recipient })));
        var headerModified = CborValue.Map(entries);

        var bytes = BuildFileWithHeader(headerModified);
        var ex = Assert.Throws<PqfFileException>(() => PqfFileReader.OpenForValidation(bytes));
        Assert.Equal(PqfRefusalReason.BinaryFieldLengthMismatch, ex.Reason);
    }

    [Fact]
    public void Reader_refuses_alg_wrong_kem_value()
    {
        var alg = CborValue.Map(new List<KeyValuePair<CborValue, CborValue>>
        {
            new(CborValue.Text("aead"), CborValue.Text("aes-256-gcm-chunked")),
            new(CborValue.Text("combiner"), CborValue.Text("x-wing")),
            new(CborValue.Text("kdf"), CborValue.Text("hkdf-sha256")),
            new(CborValue.Text("kem"), CborValue.Text("wrong-kem")), // Wrong value
            new(CborValue.Text("sig"), CborValue.Text("ed25519+ml-dsa-87")),
        });

        var header = BuildValidHeaderCbor();
        var entries = ((CborValue.MapValue)header).Entries.ToList();
        entries = entries.Where(x => ((CborValue.TextValue)x.Key).Value != "alg").ToList();
        entries.Add(new(CborValue.Text("alg"), alg));
        var headerModified = CborValue.Map(entries);

        var bytes = BuildFileWithHeader(headerModified);
        var ex = Assert.Throws<PqfFileException>(() => PqfFileReader.OpenForValidation(bytes));
        Assert.Equal(PqfRefusalReason.AlgorithmIdentifierMismatch, ex.Reason);
    }

    private static CborValue BuildValidHeaderCbor()
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

    private static byte[] BuildFileWithHeader(CborValue header)
    {
        var encodedHeader = DeterministicCborEncoder.Encode(header);
        var buffer = new byte[10 + encodedHeader.Length + 20];

        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(buffer, 0x50514631); // "PQF1"
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(buffer.AsSpan(4), 0x0001);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(6), (uint)encodedHeader.Length);
        encodedHeader.CopyTo(buffer.AsMemory(10));

        // Add minimal footer
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(buffer.AsSpan(10 + encodedHeader.Length), 0x50514645); // "PQFE"
        System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(buffer.AsSpan(10 + encodedHeader.Length + 4), 0); // chunk count
        System.Buffers.Binary.BinaryPrimitives.WriteInt64BigEndian(buffer.AsSpan(10 + encodedHeader.Length + 12), 0); // plaintext bytes

        return buffer;
    }
}
