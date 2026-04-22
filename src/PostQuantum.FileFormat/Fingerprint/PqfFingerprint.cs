using System.Security.Cryptography;
using PostQuantum.FileFormat.Keys;

namespace PostQuantum.FileFormat.Fingerprint;

public static class PqfFingerprint
{
    public const int ByteLength = 32;
    public const int ShortFormByteLength = 8;

    /// <summary>
    /// Fingerprints are for human verification only and MUST NOT be used as identifiers for cryptographic operations, database keys, or automated identity matching.
    /// </summary>
    public static byte[] Compute(PqfPublicKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return SHA256.HashData(key.ToCanonicalBinary());
    }

    /// <summary>
    /// Fingerprints are for human verification only and MUST NOT be used as identifiers for cryptographic operations, database keys, or automated identity matching.
    /// </summary>
    public static byte[] Compute(PqfSigningPublicKey key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return SHA256.HashData(key.ToCanonicalBinary());
    }

    public static string ToHex(ReadOnlySpan<byte> fingerprint)
    {
        ValidateLength(fingerprint, ByteLength);
        return Convert.ToHexString(fingerprint).ToLowerInvariant();
    }

    public static string ToShortHex(ReadOnlySpan<byte> fingerprint)
    {
        ValidateLength(fingerprint, ByteLength);
        return Convert.ToHexString(fingerprint[..ShortFormByteLength]).ToLowerInvariant();
    }

    public static string ToPrefixedHex(ReadOnlySpan<byte> fingerprint)
    {
        return $"pqf1fp:{ToHex(fingerprint)}";
    }

    private static void ValidateLength(ReadOnlySpan<byte> fingerprint, int expectedLength)
    {
        if (fingerprint.Length != expectedLength)
        {
            throw new ArgumentException($"Fingerprint must be exactly {expectedLength} bytes.", nameof(fingerprint));
        }
    }
}