using PostQuantum.FileFormat.Keys;

namespace PostQuantum.FileFormat.Tests.Keys;

public sealed class PqfPublicKeyTests
{
    [Fact]
    public void PqfPublicKey_roundtrip_preserves_bytes()
    {
        var bytes = BuildCanonicalBytes(PqfPublicKey.Version, 0x42, 0x13);
        var key = PqfPublicKey.FromCanonicalBinary(bytes);
        Assert.Equal(bytes, key.ToCanonicalBinary());
    }

    [Fact]
    public void PqfPublicKey_rejects_wrong_length()
    {
        var wrongLength = new byte[PqfPublicKey.CanonicalByteLength - 1];
        var ex = Assert.Throws<KeyFormatException>(() => PqfPublicKey.FromCanonicalBinary(wrongLength));
        Assert.Contains("exactly", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void PqfPublicKey_rejects_wrong_version_byte()
    {
        var bytes = BuildCanonicalBytes(version: 0xFF, x25519Byte: 0x42, mlkemByte: 0x13);
        var ex = Assert.Throws<KeyFormatException>(() => PqfPublicKey.FromCanonicalBinary(bytes));
        Assert.Contains("version", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void PqfPublicKey_total_length_is_1217()
    {
        var bytes = BuildCanonicalBytes(PqfPublicKey.Version, 0x01, 0x02);
        var key = PqfPublicKey.FromCanonicalBinary(bytes);
        Assert.Equal(1217, key.ToCanonicalBinary().Length);
    }

    private static byte[] BuildCanonicalBytes(byte version, byte x25519Byte, byte mlkemByte)
    {
        var bytes = new byte[PqfPublicKey.CanonicalByteLength];
        bytes[0] = version;
        Array.Fill(bytes, x25519Byte, 1, 32);
        Array.Fill(bytes, mlkemByte, 33, 1184);
        return bytes;
    }
}