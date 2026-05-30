using PostQuantum.FileFormat.Crypto;
using PostQuantum.FileFormat.Keys;

namespace PostQuantum.FileFormat.Tests.Crypto;

public sealed class HybridSignerTests
{
    private static readonly byte[] Domain = HybridSigner.HeaderSignatureDomain;

    [Fact]
    public void Sign_then_verify_roundtrip()
    {
        var provider = CryptoProvider.Detect();
        using var identity = PqfSigningIdentity.Generate(provider);
        var signer = new HybridSigner(provider);
        var message = RandomBytes(512);

        var signature = signer.Sign(identity, Domain, message);
        Assert.Equal(HybridSigner.HybridSignatureLength, signature.Length);
        Assert.True(signer.Verify(identity.PublicKey, Domain, message, signature));
    }

    [Fact]
    public void Verify_fails_on_tampered_halves_and_wrong_length()
    {
        var provider = CryptoProvider.Detect();
        using var identity = PqfSigningIdentity.Generate(provider);
        var signer = new HybridSigner(provider);
        var message = RandomBytes(128);
        var signature = signer.Sign(identity, Domain, message);

        var tamperedClassical = signature.ToArray();
        tamperedClassical[0] ^= 0x01;
        Assert.False(signer.Verify(identity.PublicKey, Domain, message, tamperedClassical));

        var tamperedPqc = signature.ToArray();
        tamperedPqc[200] ^= 0x01;
        Assert.False(signer.Verify(identity.PublicKey, Domain, message, tamperedPqc));

        Assert.False(signer.Verify(identity.PublicKey, Domain, message, signature[..4680]));
        Assert.False(signer.Verify(identity.PublicKey, Domain, message, signature.Concat(new byte[] { 0 }).ToArray()));
    }

    [Fact]
    public void Verify_fails_when_domain_differs()
    {
        // Domain separation (#1): a signature produced under the header-sig
        // domain must NOT verify under the file-sig domain for the same bytes.
        var provider = CryptoProvider.Detect();
        using var identity = PqfSigningIdentity.Generate(provider);
        var signer = new HybridSigner(provider);
        var message = RandomBytes(68);

        var headerSig = signer.Sign(identity, HybridSigner.HeaderSignatureDomain, message);

        Assert.True(signer.Verify(identity.PublicKey, HybridSigner.HeaderSignatureDomain, message, headerSig));
        Assert.False(signer.Verify(identity.PublicKey, HybridSigner.FileSignatureDomain, message, headerSig));
    }

    private static byte[] RandomBytes(int n)
    {
        var b = new byte[n];
        System.Security.Cryptography.RandomNumberGenerator.Fill(b);
        return b;
    }
}
