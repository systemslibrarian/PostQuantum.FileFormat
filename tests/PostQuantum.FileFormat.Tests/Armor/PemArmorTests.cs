using PostQuantum.FileFormat.Armor;
using PostQuantum.FileFormat.Keys;

namespace PostQuantum.FileFormat.Tests.Armor;

public sealed class PemArmorTests
{
    [Fact]
    public void ArmorPublicKey_produces_standard_pem_structure()
    {
        var key = BuildPublicKey(0x42, 0x13);
        var pem = PemArmor.ArmorPublicKey(key);

        Assert.StartsWith("-----BEGIN PQF PUBLIC KEY-----", pem, StringComparison.Ordinal);
        Assert.Contains("-----END PQF PUBLIC KEY-----", pem, StringComparison.Ordinal);
    }

    [Fact]
    public void ArmorPublicKey_wraps_at_64_characters()
    {
        var key = BuildPublicKey(0x42, 0x13);
        var pem = PemArmor.ArmorPublicKey(key);
        var lines = pem.Split('\n', StringSplitOptions.RemoveEmptyEntries);

        foreach (var line in lines.Skip(1).SkipLast(1))
        {
            Assert.True(line.Length <= 64, $"Body line exceeds 64 chars: {line.Length}");
        }
    }

    [Fact]
    public void ArmorPublicKey_uses_exact_label_string()
    {
        var key = BuildPublicKey(0x42, 0x13);
        var pem = PemArmor.ArmorPublicKey(key);

        Assert.Contains($"-----BEGIN {PemArmor.PublicKeyLabel}-----", pem, StringComparison.Ordinal);
        Assert.Contains($"-----END {PemArmor.PublicKeyLabel}-----", pem, StringComparison.Ordinal);
    }

    [Fact]
    public void Roundtrip_publicKey_PEM_is_byte_identical()
    {
        var key = BuildPublicKey(0x42, 0x13);
        var pem = PemArmor.ArmorPublicKey(key);
        var decoded = PemArmor.DearmorPublicKey(pem);

        Assert.Equal(key.ToCanonicalBinary(), decoded.ToCanonicalBinary());
    }

    [Fact]
    public void Roundtrip_signingPublicKey_PEM_is_byte_identical()
    {
        var key = BuildSigningPublicKey(0x24, 0x68);
        var pem = PemArmor.ArmorSigningPublicKey(key);
        var decoded = PemArmor.DearmorSigningPublicKey(pem);

        Assert.Equal(key.ToCanonicalBinary(), decoded.ToCanonicalBinary());
    }

    [Fact]
    public void Dearmor_accepts_crlf_line_endings()
    {
        var pem = PemArmor.ArmorPublicKey(BuildPublicKey(0x42, 0x13)).Replace("\n", "\r\n", StringComparison.Ordinal);
        var decoded = PemArmor.DearmorPublicKey(pem);
        Assert.Equal(PqfPublicKey.CanonicalByteLength, decoded.ToCanonicalBinary().Length);
    }

    [Fact]
    public void Dearmor_accepts_lf_line_endings()
    {
        var pem = PemArmor.ArmorPublicKey(BuildPublicKey(0x42, 0x13));
        var decoded = PemArmor.DearmorPublicKey(pem);
        Assert.Equal(PqfPublicKey.CanonicalByteLength, decoded.ToCanonicalBinary().Length);
    }

    [Fact]
    public void Dearmor_rejects_mismatched_label()
    {
        var signingPem = PemArmor.ArmorSigningPublicKey(BuildSigningPublicKey(0x24, 0x68));
        Assert.Throws<FormatException>(() => PemArmor.DearmorPublicKey(signingPem));
    }

    [Fact]
    public void Dearmor_rejects_truncated_base64()
    {
        var pem = PemArmor.ArmorPublicKey(BuildPublicKey(0x42, 0x13));
        var truncated = pem.Remove(pem.LastIndexOf('='), 1);
        Assert.Throws<FormatException>(() => PemArmor.DearmorPublicKey(truncated));
    }

    [Fact]
    public void Dearmor_rejects_wrong_canonical_length()
    {
        var raw = new byte[10];
        var b64 = Convert.ToBase64String(raw);
        var pem = $"-----BEGIN {PemArmor.PublicKeyLabel}-----\n{b64}\n-----END {PemArmor.PublicKeyLabel}-----\n";

        Assert.Throws<KeyFormatException>(() => PemArmor.DearmorPublicKey(pem));
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