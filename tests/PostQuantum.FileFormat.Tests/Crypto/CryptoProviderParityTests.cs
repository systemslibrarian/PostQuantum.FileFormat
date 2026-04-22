using PostQuantum.FileFormat.Crypto;

namespace PostQuantum.FileFormat.Tests.Crypto;

public sealed class CryptoProviderParityTests
{
    [Fact]
    public void Bcl_support_flag_is_exposed()
    {
        _ = BclCryptoProvider.IsSupported;
    }

    [Fact]
    public void MlKem_cross_provider_parity_when_bcl_supported()
    {
        if (!BclCryptoProvider.IsSupported)
        {
            return;
        }

        var bcl = new BclCryptoProvider();
        var bc = new BouncyCastleCryptoProvider();

        var (sk, pk) = bcl.MlKem1024GenerateKeyPair();
        var (ss1, ct) = bc.MlKem1024Encapsulate(pk);
        var ss2 = bcl.MlKem1024Decapsulate(sk, ct);

        Assert.Equal(ss1, ss2);
    }

    [Fact]
    public void X25519_self_consistency()
    {
        var provider = CryptoProvider.Detect();
        var (aSk, aPk) = provider.X25519GenerateKeyPair();
        var (bSk, bPk) = provider.X25519GenerateKeyPair();

        var ss1 = provider.X25519DeriveSharedSecret(aSk, bPk);
        var ss2 = provider.X25519DeriveSharedSecret(bSk, aPk);

        Assert.Equal(ss1, ss2);
    }
}
