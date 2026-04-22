using PostQuantum.FileFormat.Crypto;
using PostQuantum.FileFormat.Keys;

namespace PostQuantum.FileFormat.Tests.Crypto;

public sealed class HybridSignerTests
{
    [Fact]
    public void Sign_then_verify_roundtrip()
    {
        var provider = CryptoProvider.Detect();
        using var identity = PqfSigningIdentity.Generate(provider);
        var signer = new HybridSigner(provider);
        var message = RandomBytes(512);

        var signature = signer.Sign(identity, message);
        Assert.Equal(HybridSigner.HybridSignatureLength, signature.Length);
        Assert.True(signer.Verify(identity.PublicKey, message, signature));
    }

    [Fact]
    public void Verify_fails_on_tampered_halves_and_wrong_length()
    {
        var provider = CryptoProvider.Detect();
        using var identity = PqfSigningIdentity.Generate(provider);
        var signer = new HybridSigner(provider);
        var message = RandomBytes(128);
        var signature = signer.Sign(identity, message);

        var tamperedClassical = signature.ToArray();
        tamperedClassical[0] ^= 0x01;
        Assert.False(signer.Verify(identity.PublicKey, message, tamperedClassical));

        var tamperedPqc = signature.ToArray();
        tamperedPqc[200] ^= 0x01;
        Assert.False(signer.Verify(identity.PublicKey, message, tamperedPqc));

        Assert.False(signer.Verify(identity.PublicKey, message, signature[..4680]));
        Assert.False(signer.Verify(identity.PublicKey, message, signature.Concat(new byte[] { 0 }).ToArray()));
    }

    private static byte[] RandomBytes(int n)
    {
        var b = new byte[n];
        System.Security.Cryptography.RandomNumberGenerator.Fill(b);
        return b;
    }
}
