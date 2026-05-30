using PostQuantum.FileFormat.Armor;
using PostQuantum.FileFormat.Fingerprint;
using PostQuantum.FileFormat.Keys;

namespace PostQuantum.FileFormat.Tests.Integration;

public sealed class PublicKeyIntegrationTests
{
    [Fact]
    public void Integration_publicKey_roundtrips_through_canonical_pem_and_fingerprint()
    {
        var x25519 = Enumerable.Repeat((byte)0x42, 32).ToArray();
        var mlkem = Enumerable.Repeat((byte)0x13, 1184).ToArray();
        var key = PqfPublicKey.FromCanonicalBinary(BuildBytes(PqfPublicKey.Version, x25519, mlkem));

        var pem = PemArmor.ArmorPublicKey(key);
        var decoded = PemArmor.DearmorPublicKey(pem);
        var canonical1 = key.ToCanonicalBinary();
        var canonical2 = decoded.ToCanonicalBinary();
        var fp1 = PqfFingerprint.Compute(key);
        var fp2 = PqfFingerprint.Compute(decoded);

        Assert.Equal(canonical1, canonical2);
        Assert.Equal(fp1, fp2);
        Assert.Equal(PqfPublicKey.CanonicalByteLength, canonical1.Length);
        Assert.Equal(PqfFingerprint.ByteLength, fp1.Length);
    }

    private static byte[] BuildBytes(byte version, byte[] x25519, byte[] mlkem)
    {
        var output = new byte[PqfPublicKey.CanonicalByteLength];
        output[0] = version;
        x25519.CopyTo(output, 1);
        mlkem.CopyTo(output, 1 + x25519.Length);
        return output;
    }
}