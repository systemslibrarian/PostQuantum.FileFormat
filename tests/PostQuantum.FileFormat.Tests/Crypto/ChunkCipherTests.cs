using PostQuantum.FileFormat.Crypto;

namespace PostQuantum.FileFormat.Tests.Crypto;

public sealed class ChunkCipherTests
{
    [Fact]
    public void EncryptDecrypt_roundtrip_recovers_plaintext()
    {
        var dek = RandomBytes(32);
        var fileId = RandomBytes(16);
        var plaintext = RandomBytes(1234);
        var ciphertext = new byte[plaintext.Length + 16];

        var written = ChunkCipher.EncryptChunk(dek, 4, false, fileId, plaintext, ciphertext);
        Assert.Equal(plaintext.Length + 16, written);

        var decrypted = new byte[plaintext.Length];
        var recovered = ChunkCipher.DecryptChunk(dek, 4, false, fileId, ciphertext, decrypted);
        Assert.Equal(plaintext.Length, recovered);
        Assert.Equal(plaintext, decrypted);
    }

    [Fact]
    public void EncryptChunk_changes_with_index_and_final_flag_and_fileId()
    {
        var dek = RandomBytes(32);
        var fileIdA = RandomBytes(16);
        var fileIdB = RandomBytes(16);
        var plaintext = RandomBytes(256);

        var c1 = new byte[plaintext.Length + 16];
        var c2 = new byte[plaintext.Length + 16];
        var c3 = new byte[plaintext.Length + 16];

        ChunkCipher.EncryptChunk(dek, 0, false, fileIdA, plaintext, c1);
        ChunkCipher.EncryptChunk(dek, 1, false, fileIdA, plaintext, c2);
        ChunkCipher.EncryptChunk(dek, 0, true, fileIdB, plaintext, c3);

        Assert.NotEqual(c1, c2);
        Assert.NotEqual(c1, c3);
    }

    [Fact]
    public void DecryptChunk_returns_minus_one_on_tamper_or_aad_mismatch()
    {
        var dek = RandomBytes(32);
        var fileId = RandomBytes(16);
        var plaintext = RandomBytes(300);
        var ciphertext = new byte[plaintext.Length + 16];
        ChunkCipher.EncryptChunk(dek, 2, true, fileId, plaintext, ciphertext);

        ciphertext[0] ^= 0x01;
        var output = new byte[plaintext.Length];
        Assert.Equal(-1, ChunkCipher.DecryptChunk(dek, 2, true, fileId, ciphertext, output));

        ChunkCipher.EncryptChunk(dek, 2, true, fileId, plaintext, ciphertext);
        Assert.Equal(-1, ChunkCipher.DecryptChunk(dek, 3, true, fileId, ciphertext, output));
    }

    private static byte[] RandomBytes(int n)
    {
        var b = new byte[n];
        System.Security.Cryptography.RandomNumberGenerator.Fill(b);
        return b;
    }
}
