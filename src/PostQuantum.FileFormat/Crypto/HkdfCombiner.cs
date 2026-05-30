using System.Buffers.Binary;
using System.Security.Cryptography;

namespace PostQuantum.FileFormat.Crypto;

/// <summary>
/// Per-chunk key derivation from the DEK. The KEM-level combiner that this
/// class used to host has been removed — KEK derivation now lives in
/// <see cref="XWingKem"/> (draft-connolly-cfrg-xwing-kem). What remains is
/// the unrelated per-chunk HKDF expansion used by <see cref="ChunkCipher"/>.
/// </summary>
public static class HkdfCombiner
{
    private static readonly byte[] ChunkInfoPrefix = "PQF1-chunk-v1"u8.ToArray();

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
