using System.Security.Cryptography;

namespace PostQuantum.FileFormat.Crypto;

public static class DekWrapper
{
    public const int WrapNonceLength = 12;
    public const int WrappedDekLength = 48;

    public static (byte[] nonce, byte[] wrappedDek) Wrap(
        ReadOnlySpan<byte> kek,
        ReadOnlySpan<byte> dek,
        ReadOnlySpan<byte> fileId)
    {
        if (kek.Length != 32)
        {
            throw new ArgumentException("KEK must be 32 bytes", nameof(kek));
        }

        if (dek.Length != 32)
        {
            throw new ArgumentException("DEK must be 32 bytes", nameof(dek));
        }

        if (fileId.Length != 16)
        {
            throw new ArgumentException("file_id must be 16 bytes", nameof(fileId));
        }

        var nonce = RandomNumberGenerator.GetBytes(WrapNonceLength);
        var ciphertext = new byte[32];
        var tag = new byte[16];

        using var aes = new AesGcm(kek, tagSizeInBytes: 16);
        aes.Encrypt(nonce, dek, ciphertext, tag, fileId);

        var wrapped = new byte[WrappedDekLength];
        ciphertext.CopyTo(wrapped, 0);
        tag.CopyTo(wrapped, 32);

        SecureZero.Clear(ciphertext);
        SecureZero.Clear(tag);

        return (nonce, wrapped);
    }

    public static byte[]? Unwrap(
        ReadOnlySpan<byte> kek,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> wrappedDek,
        ReadOnlySpan<byte> fileId)
    {
        if (kek.Length != 32 || nonce.Length != WrapNonceLength || wrappedDek.Length != WrappedDekLength || fileId.Length != 16)
        {
            return null;
        }

        var ciphertext = wrappedDek[..32];
        var tag = wrappedDek[32..48];
        var dek = new byte[32];

        try
        {
            using var aes = new AesGcm(kek, tagSizeInBytes: 16);
            aes.Decrypt(nonce, ciphertext, tag, dek, fileId);
            return dek;
        }
        catch (CryptographicException)
        {
            SecureZero.Clear(dek);
            return null;
        }
    }
}
