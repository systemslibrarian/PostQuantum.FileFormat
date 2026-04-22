using System.Buffers.Binary;
using System.Security.Cryptography;

namespace PostQuantum.FileFormat.Crypto;

public static class ChunkCipher
{
    public static int EncryptChunk(
        ReadOnlySpan<byte> dek,
        ulong chunkIndex,
        bool isFinal,
        ReadOnlySpan<byte> fileId,
        ReadOnlySpan<byte> plaintext,
        Span<byte> destination)
    {
        if (destination.Length < plaintext.Length + 16)
        {
            throw new ArgumentException("Destination too small", nameof(destination));
        }

        var chunkKey = HkdfCombiner.DeriveChunkKey(dek, chunkIndex);
        Span<byte> nonce = stackalloc byte[12];
        Span<byte> aad = stackalloc byte[25];
        BuildAad(fileId, chunkIndex, isFinal, aad);

        var ciphertext = destination[..plaintext.Length];
        var tag = destination.Slice(plaintext.Length, 16);

        using var aes = new AesGcm(chunkKey, tagSizeInBytes: 16);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, aad);

        SecureZero.Clear(chunkKey);
        return plaintext.Length + 16;
    }

    public static int DecryptChunk(
        ReadOnlySpan<byte> dek,
        ulong chunkIndex,
        bool isFinal,
        ReadOnlySpan<byte> fileId,
        ReadOnlySpan<byte> ciphertext,
        Span<byte> destination)
    {
        if (ciphertext.Length < 16)
        {
            return -1;
        }

        var plaintextLength = ciphertext.Length - 16;
        if (destination.Length < plaintextLength)
        {
            return -1;
        }

        var chunkKey = HkdfCombiner.DeriveChunkKey(dek, chunkIndex);
        Span<byte> nonce = stackalloc byte[12];
        Span<byte> aad = stackalloc byte[25];
        BuildAad(fileId, chunkIndex, isFinal, aad);

        var cipher = ciphertext[..plaintextLength];
        var tag = ciphertext[plaintextLength..];

        try
        {
            using var aes = new AesGcm(chunkKey, tagSizeInBytes: 16);
            aes.Decrypt(nonce, cipher, tag, destination[..plaintextLength], aad);
            return plaintextLength;
        }
        catch (CryptographicException)
        {
            return -1;
        }
        finally
        {
            SecureZero.Clear(chunkKey);
        }
    }

    private static void BuildAad(ReadOnlySpan<byte> fileId, ulong chunkIndex, bool isFinal, Span<byte> destination)
    {
        if (fileId.Length != 16)
        {
            throw new ArgumentException("file_id must be 16 bytes", nameof(fileId));
        }

        fileId.CopyTo(destination[..16]);
        BinaryPrimitives.WriteUInt64BigEndian(destination.Slice(16, 8), chunkIndex);
        destination[24] = isFinal ? (byte)0x01 : (byte)0x00;
    }
}
