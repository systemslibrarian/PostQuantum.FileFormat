using System.Buffers.Binary;
using System.Security.Cryptography;

namespace PostQuantum.FileFormat.Crypto;

public static class HkdfCombiner
{
    private static readonly byte[] CombinerLabel = "PQF1-combiner-v1"u8.ToArray();
    private static readonly byte[] KekInfo = "PQF1-kek-v1"u8.ToArray();
    private static readonly byte[] ChunkInfoPrefix = "PQF1-chunk-v1"u8.ToArray();

    public static byte[] DeriveKek(
        ReadOnlySpan<byte> x25519SharedSecret,
        ReadOnlySpan<byte> mlkemSharedSecret,
        ReadOnlySpan<byte> fileId,
        uint recipientIndex)
    {
        if (x25519SharedSecret.Length != 32)
        {
            throw new ArgumentException("x25519 shared secret must be 32 bytes", nameof(x25519SharedSecret));
        }

        if (mlkemSharedSecret.Length != 32)
        {
            throw new ArgumentException("mlkem shared secret must be 32 bytes", nameof(mlkemSharedSecret));
        }

        if (fileId.Length != 16)
        {
            throw new ArgumentException("file_id must be 16 bytes", nameof(fileId));
        }

        var salt = new byte[CombinerLabel.Length + 16 + 4];
        CombinerLabel.CopyTo(salt.AsSpan());
        fileId.CopyTo(salt.AsSpan(CombinerLabel.Length, 16));
        BinaryPrimitives.WriteUInt32BigEndian(salt.AsSpan(CombinerLabel.Length + 16, 4), recipientIndex);

        var ikm = new byte[64];
        x25519SharedSecret.CopyTo(ikm.AsSpan(0, 32));
        mlkemSharedSecret.CopyTo(ikm.AsSpan(32, 32));

        var prk = HKDF.Extract(HashAlgorithmName.SHA256, ikm, salt);
        var kek = HKDF.Expand(HashAlgorithmName.SHA256, prk, 32, KekInfo);

        SecureZero.Clear(ikm);
        SecureZero.Clear(prk);
        SecureZero.Clear(salt);

        return kek;
    }

    public static byte[] DeriveChunkKey(ReadOnlySpan<byte> dek, ulong chunkIndex)
    {
        if (dek.Length != 32)
        {
            throw new ArgumentException("DEK must be 32 bytes", nameof(dek));
        }

        var info = new byte[ChunkInfoPrefix.Length + 8];
        ChunkInfoPrefix.CopyTo(info.AsSpan());
        BinaryPrimitives.WriteUInt64BigEndian(info.AsSpan(ChunkInfoPrefix.Length, 8), chunkIndex);

        // HKDF.Expand's byte[]-PRK overload requires a managed array; copying the
        // DEK into a local buffer that we explicitly zero afterwards prevents the
        // secret from lingering on the GC heap (the issue with .ToArray() was that
        // the resulting array was unreachable but unzeroed until collection).
        var prk = new byte[32];
        try
        {
            dek.CopyTo(prk);
            var chunkKey = HKDF.Expand(HashAlgorithmName.SHA256, prk, 32, info);
            SecureZero.Clear(info);
            return chunkKey;
        }
        finally
        {
            SecureZero.Clear(prk);
        }
    }
}
