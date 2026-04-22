using PostQuantum.FileFormat.File;
using PostQuantum.FileFormat.Keys;

namespace PostQuantum.FileFormat.Tests.File;

public sealed class EncryptDecryptRoundtripTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(100)]
    [InlineData(4096)]
    [InlineData(65535)]
    [InlineData(65536)]
    [InlineData(65537)]
    [InlineData(1_000_000)]
    public async Task Roundtrip_unsigned_single_recipient(int plaintextSize)
    {
        using var identity = PqfIdentity.Generate();
        var plaintext = RandomBytes(plaintextSize);

        using var encrypted = new MemoryStream();
        await PqfFileWriter.EncryptAsync(new MemoryStream(plaintext), encrypted, new[] { identity.PublicKey }, signer: null);

        encrypted.Position = 0;
        using var decrypted = new MemoryStream();
        await PqfFileReader.DecryptAsync(encrypted, decrypted, identity);

        Assert.Equal(plaintext, decrypted.ToArray());
    }

    [Fact]
    public async Task Roundtrip_signed_multi_recipient()
    {
        using var id1 = PqfIdentity.Generate();
        using var id2 = PqfIdentity.Generate();
        using var signer = PqfSigningIdentity.Generate();

        var plaintext = RandomBytes(300_000);
        using var encrypted = new MemoryStream();
        await PqfFileWriter.EncryptAsync(new MemoryStream(plaintext), encrypted, new[] { id1.PublicKey, id2.PublicKey }, signer);

        encrypted.Position = 0;
        using var decrypted = new MemoryStream();
        await PqfFileReader.DecryptAsync(encrypted, decrypted, id2);

        Assert.Equal(plaintext, decrypted.ToArray());
    }

    [Fact]
    public async Task Decrypt_wrong_identity_refuses()
    {
        using var right = PqfIdentity.Generate();
        using var wrong = PqfIdentity.Generate();

        var plaintext = RandomBytes(1024);
        using var encrypted = new MemoryStream();
        await PqfFileWriter.EncryptAsync(new MemoryStream(plaintext), encrypted, new[] { right.PublicKey }, signer: null);

        encrypted.Position = 0;
        using var decrypted = new MemoryStream();
        var ex = await Assert.ThrowsAsync<PqfFileException>(() => PqfFileReader.DecryptAsync(encrypted, decrypted, wrong));
        Assert.Equal(PqfRefusalReason.IdentityMatchesNoRecipient, ex.Reason);
    }

    [Fact]
    public async Task Decrypt_tampered_chunk_refuses()
    {
        using var identity = PqfIdentity.Generate();
        var plaintext = RandomBytes(5000);
        using var encrypted = new MemoryStream();
        await PqfFileWriter.EncryptAsync(new MemoryStream(plaintext), encrypted, new[] { identity.PublicKey }, signer: null);

        var bytes = encrypted.ToArray();
        var reader = PqfFileReader.OpenForValidation(bytes);
        var offset = 10 + ((int)System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(6, 4)));
        if (reader.Header.Signer != null)
        {
            offset += 4691;
        }

        // First chunk starts here: 4-byte len + 1-byte flags + payload.
        var firstChunkLen = (int)System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(offset, 4));
        bytes[offset + 5 + Math.Min(10, firstChunkLen - 1)] ^= 0x01;

        using var tampered = new MemoryStream(bytes);
        using var decrypted = new MemoryStream();
        var ex = await Assert.ThrowsAsync<PqfFileException>(() => PqfFileReader.DecryptAsync(tampered, decrypted, identity));
        Assert.Equal(PqfRefusalReason.AeadTagFailure, ex.Reason);
    }

    private static byte[] RandomBytes(int n)
    {
        var b = new byte[n];
        System.Security.Cryptography.RandomNumberGenerator.Fill(b);
        return b;
    }
}
