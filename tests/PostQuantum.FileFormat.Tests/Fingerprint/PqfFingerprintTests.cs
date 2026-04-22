using PostQuantum.FileFormat.Fingerprint;
using PostQuantum.FileFormat.Keys;
using System.Text.RegularExpressions;

namespace PostQuantum.FileFormat.Tests.Fingerprint;

public sealed class PqfFingerprintTests
{
    [Fact]
    public void Compute_publicKey_produces_32_bytes()
    {
        var key = BuildPublicKey(0x42, 0x13);
        var fp = PqfFingerprint.Compute(key);
        Assert.Equal(32, fp.Length);
    }

    [Fact]
    public void Compute_signingPublicKey_produces_32_bytes()
    {
        var key = BuildSigningPublicKey(0x22, 0x44);
        var fp = PqfFingerprint.Compute(key);
        Assert.Equal(32, fp.Length);
    }

    [Fact]
    public void Compute_same_key_produces_same_fingerprint()
    {
        var key = BuildPublicKey(0x42, 0x13);
        Assert.Equal(PqfFingerprint.Compute(key), PqfFingerprint.Compute(key));
    }

    [Fact]
    public void Compute_different_keys_produce_different_fingerprints()
    {
        var key1 = BuildPublicKey(0x42, 0x13);
        var key2 = BuildPublicKey(0x41, 0x13);
        Assert.NotEqual(PqfFingerprint.Compute(key1), PqfFingerprint.Compute(key2));
    }

    [Fact]
    public void ToHex_produces_64_lowercase_hex_chars()
    {
        var fp = PqfFingerprint.Compute(BuildPublicKey(0x42, 0x13));
        var text = PqfFingerprint.ToHex(fp);

        Assert.Equal(64, text.Length);
        Assert.Matches(new Regex("^[0-9a-f]{64}$", RegexOptions.CultureInvariant), text);
    }

    [Fact]
    public void ToShortHex_produces_16_lowercase_hex_chars()
    {
        var fp = PqfFingerprint.Compute(BuildPublicKey(0x42, 0x13));
        var text = PqfFingerprint.ToShortHex(fp);

        Assert.Equal(16, text.Length);
        Assert.Matches(new Regex("^[0-9a-f]{16}$", RegexOptions.CultureInvariant), text);
    }

    [Fact]
    public void ToPrefixedHex_starts_with_pqf1fp_colon()
    {
        var fp = PqfFingerprint.Compute(BuildPublicKey(0x42, 0x13));
        var text = PqfFingerprint.ToPrefixedHex(fp);
        Assert.StartsWith("pqf1fp:", text, StringComparison.Ordinal);
    }

    [Fact]
    public void Compute_all_zero_publicKey_matches_known_answer()
    {
        var key = BuildPublicKey(x25519Fill: 0x00, mlkemFill: 0x00);
        var fp = PqfFingerprint.Compute(key);
        var hex = PqfFingerprint.ToHex(fp);

        Assert.Equal("95d6ad1d6f4d825c4410bc95235c4d1c584566518e0a14b4ed5548d6b10124f9", hex);
    }

    private static PqfPublicKey BuildPublicKey(byte x25519Fill, byte mlkemFill)
    {
        var bytes = new byte[PqfPublicKey.CanonicalByteLength];
        bytes[0] = PqfPublicKey.Version;
        Array.Fill(bytes, x25519Fill, 1, 32);
        Array.Fill(bytes, mlkemFill, 33, 1568);
        return PqfPublicKey.FromCanonicalBinary(bytes);
    }

    private static PqfSigningPublicKey BuildSigningPublicKey(byte ed25519Fill, byte mldsaFill)
    {
        var bytes = new byte[PqfSigningPublicKey.CanonicalByteLength];
        bytes[0] = PqfSigningPublicKey.Version;
        Array.Fill(bytes, ed25519Fill, 1, 32);
        Array.Fill(bytes, mldsaFill, 33, 2592);
        return PqfSigningPublicKey.FromCanonicalBinary(bytes);
    }
}