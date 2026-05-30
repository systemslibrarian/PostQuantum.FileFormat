using System.Buffers.Binary;
using System.Security.Cryptography;

namespace PostQuantum.FileFormat.Crypto;

/// <summary>
/// Wraps the per-file DEK under each recipient's KEK with AES-256-GCM.
///
/// The associated data binds the wrap to both the file instance and the
/// recipient slot:
///
///   aad = file_id (16 bytes) || recipient_index (uint32 BE)
///
/// X-Wing's KEM combiner has no salt for these bindings (unlike the prior
/// PQF in-house HKDF combiner, which mixed file_id + recipient_index into
/// the HKDF salt). Re-binding them at the AEAD layer preserves the same
/// security properties: a KEK derived for recipient i cannot unwrap a DEK
/// wrap targeted at recipient j (the AADs differ), and a KEK from one file
/// cannot unwrap a wrap from another (file_ids differ).
/// </summary>
public static class DekWrapper
{
    public const int WrapNonceLength = 12;
    public const int WrappedDekLength = 48;
    public const int AadLength = 16 + 4;

    public static (byte[] nonce, byte[] wrappedDek) Wrap(
        ReadOnlySpan<byte> kek,
        ReadOnlySpan<byte> dek,
        ReadOnlySpan<byte> fileId,
        uint recipientIndex)
    {
        var nonce = RandomNumberGenerator.GetBytes(WrapNonceLength);
        return WrapWithNonce(kek, dek, fileId, recipientIndex, nonce);
    }

    internal static (byte[] nonce, byte[] wrappedDek) Wrap(
        ReadOnlySpan<byte> kek,
        ReadOnlySpan<byte> dek,
        ReadOnlySpan<byte> fileId,
        uint recipientIndex,
        ReadOnlySpan<byte> nonce)
    {
        return WrapWithNonce(kek, dek, fileId, recipientIndex, nonce);
    }

    private static (byte[] nonce, byte[] wrappedDek) WrapWithNonce(
        ReadOnlySpan<byte> kek,
        ReadOnlySpan<byte> dek,
        ReadOnlySpan<byte> fileId,
        uint recipientIndex,
        ReadOnlySpan<byte> nonce)
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

        if (nonce.Length != WrapNonceLength)
        {
            throw new ArgumentException("nonce must be 12 bytes", nameof(nonce));
        }

        var nonceCopy = nonce.ToArray();
        var aad = BuildAad(fileId, recipientIndex);
        var ciphertext = new byte[32];
        var tag = new byte[16];

        using var aes = new AesGcm(kek, tagSizeInBytes: 16);
        aes.Encrypt(nonceCopy, dek, ciphertext, tag, aad);

        var wrapped = new byte[WrappedDekLength];
        ciphertext.CopyTo(wrapped, 0);
        tag.CopyTo(wrapped, 32);

        SecureZero.Clear(ciphertext);
        SecureZero.Clear(tag);
        SecureZero.Clear(aad);

        return (nonceCopy, wrapped);
    }

    public static byte[]? Unwrap(
        ReadOnlySpan<byte> kek,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> wrappedDek,
        ReadOnlySpan<byte> fileId,
        uint recipientIndex)
    {
        if (kek.Length != 32 || nonce.Length != WrapNonceLength || wrappedDek.Length != WrappedDekLength || fileId.Length != 16)
        {
            return null;
        }

        var aad = BuildAad(fileId, recipientIndex);
        var ciphertext = wrappedDek[..32];
        var tag = wrappedDek[32..48];
        var dek = new byte[32];

        try
        {
            using var aes = new AesGcm(kek, tagSizeInBytes: 16);
            aes.Decrypt(nonce, ciphertext, tag, dek, aad);
            return dek;
        }
        catch (CryptographicException)
        {
            SecureZero.Clear(dek);
            return null;
        }
        finally
        {
            SecureZero.Clear(aad);
        }
    }

    private static byte[] BuildAad(ReadOnlySpan<byte> fileId, uint recipientIndex)
    {
        var aad = new byte[AadLength];
        fileId.CopyTo(aad.AsSpan(0, 16));
        BinaryPrimitives.WriteUInt32BigEndian(aad.AsSpan(16, 4), recipientIndex);
        return aad;
    }
}
