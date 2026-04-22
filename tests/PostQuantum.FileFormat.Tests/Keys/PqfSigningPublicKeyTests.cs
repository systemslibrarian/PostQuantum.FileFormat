using PostQuantum.FileFormat.Keys;

namespace PostQuantum.FileFormat.Tests.Keys;

public sealed class PqfSigningPublicKeyTests
{
    [Fact]
    public void PqfSigningPublicKey_roundtrip_preserves_bytes()
    {
        var bytes = BuildCanonicalBytes(PqfSigningPublicKey.Version, 0x21, 0x34);
        var key = PqfSigningPublicKey.FromCanonicalBinary(bytes);
        Assert.Equal(bytes, key.ToCanonicalBinary());
    }

    [Fact]
    public void PqfSigningPublicKey_rejects_wrong_length()
    {
        var wrongLength = new byte[PqfSigningPublicKey.CanonicalByteLength - 1];
        var ex = Assert.Throws<KeyFormatException>(() => PqfSigningPublicKey.FromCanonicalBinary(wrongLength));
        Assert.Contains("exactly", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void PqfSigningPublicKey_rejects_wrong_version_byte()
    {
        var bytes = BuildCanonicalBytes(version: 0xFE, ed25519Byte: 0x21, mldsaByte: 0x34);
        var ex = Assert.Throws<KeyFormatException>(() => PqfSigningPublicKey.FromCanonicalBinary(bytes));
        Assert.Contains("version", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void PqfSigningPublicKey_total_length_is_2625()
    {
        var bytes = BuildCanonicalBytes(PqfSigningPublicKey.Version, 0x11, 0x22);
        var key = PqfSigningPublicKey.FromCanonicalBinary(bytes);
        Assert.Equal(2625, key.ToCanonicalBinary().Length);
    }

    private static byte[] BuildCanonicalBytes(byte version, byte ed25519Byte, byte mldsaByte)
    {
        var bytes = new byte[PqfSigningPublicKey.CanonicalByteLength];
        bytes[0] = version;
        Array.Fill(bytes, ed25519Byte, 1, 32);
        Array.Fill(bytes, mldsaByte, 33, 2592);
        return bytes;
    }
}