using PostQuantum.FileFormat.Crypto;
using PostQuantum.FileFormat.Keys;

namespace PostQuantum.FileFormat.Tests.Crypto;

public sealed class XWingKemTests
{
    [Fact]
    public void Label_is_exactly_the_six_bytes_5C_2E_2F_2F_5E_5C()
    {
        // draft-connolly-cfrg-xwing-kem specifies the label as the literal
        // 6-byte ASCII art "\.//^\". Any deviation (including the ASCII
        // string "X-Wing") would silently fail interop with conforming
        // X-Wing implementations. This test pins the byte sequence.
        var expected = new byte[] { 0x5C, 0x2E, 0x2F, 0x2F, 0x5E, 0x5C };
        Assert.Equal(expected, XWingKem.Label.ToArray());
    }

    [Fact]
    public void Encap_decap_roundtrip_recovers_same_shared_secret()
    {
        var provider = CryptoProvider.Detect();
        using var identity = PqfIdentity.Generate(provider);
        var kem = new XWingKem(provider);

        var (epk, ct, ssA) = kem.Encapsulate(
            identity.PublicKey.MlKem768PublicKey.Span,
            identity.PublicKey.X25519PublicKey.Span);

        var ssB = kem.Decapsulate(
            identity.MlKem768PrivateKey.Span,
            identity.X25519PrivateKey.Span,
            identity.PublicKey.X25519PublicKey.Span,
            epk,
            ct);

        Assert.Equal(32, ssA.Length);
        Assert.Equal(ssA, ssB);
    }

    [Fact]
    public void Distinct_encaps_to_same_recipient_diverge()
    {
        // Both ct_M and ct_X are freshly random per call; the SHA-3 combiner
        // mixes both in, so the shared secret must diverge.
        var provider = CryptoProvider.Detect();
        using var identity = PqfIdentity.Generate(provider);
        var kem = new XWingKem(provider);

        var (_, _, ssA) = kem.Encapsulate(
            identity.PublicKey.MlKem768PublicKey.Span,
            identity.PublicKey.X25519PublicKey.Span);
        var (_, _, ssB) = kem.Encapsulate(
            identity.PublicKey.MlKem768PublicKey.Span,
            identity.PublicKey.X25519PublicKey.Span);

        Assert.NotEqual(ssA, ssB);
    }

    [Fact]
    public void Decap_with_wrong_ctX_yields_different_ss()
    {
        // X-Wing binds ct_X into the SHA-3 input. Tamper with ct_X and
        // the recovered ss must diverge (ML-KEM's implicit rejection means
        // ssM stays valid-looking; the divergence is from ct_X alone).
        var provider = CryptoProvider.Detect();
        using var identity = PqfIdentity.Generate(provider);
        var kem = new XWingKem(provider);

        var (epk, ct, ssGood) = kem.Encapsulate(
            identity.PublicKey.MlKem768PublicKey.Span,
            identity.PublicKey.X25519PublicKey.Span);

        var tampered = (byte[])epk.Clone();
        tampered[0] ^= 0x01;

        var ssBad = kem.Decapsulate(
            identity.MlKem768PrivateKey.Span,
            identity.X25519PrivateKey.Span,
            identity.PublicKey.X25519PublicKey.Span,
            tampered,
            ct);

        Assert.NotEqual(ssGood, ssBad);
    }

    [Fact]
    public void Decap_with_wrong_pkX_in_combiner_yields_different_ss()
    {
        // X-Wing binds pk_X (the recipient's X25519 public key) into the
        // combiner. Passing a different pk_X to Decapsulate yields a
        // divergent ss even though the underlying ss_M and ss_X are correct.
        // This is the "pk binding" property that the old PQF combiner lacked.
        var provider = CryptoProvider.Detect();
        using var identity = PqfIdentity.Generate(provider);
        var kem = new XWingKem(provider);

        var (epk, ct, ssGood) = kem.Encapsulate(
            identity.PublicKey.MlKem768PublicKey.Span,
            identity.PublicKey.X25519PublicKey.Span);

        var bogusPkX = new byte[32];
        System.Security.Cryptography.RandomNumberGenerator.Fill(bogusPkX);

        var ssBad = kem.Decapsulate(
            identity.MlKem768PrivateKey.Span,
            identity.X25519PrivateKey.Span,
            bogusPkX,
            epk,
            ct);

        Assert.NotEqual(ssGood, ssBad);
    }

    [Fact]
    public void Sizes_match_draft_constants()
    {
        Assert.Equal(32, XWingKem.SharedSecretLength);
        Assert.Equal(1088, XWingKem.MlKem768CiphertextLength);
        Assert.Equal(32, XWingKem.X25519PublicKeyLength);
        Assert.Equal(32, XWingKem.MlKem768SharedSecretLength);
        Assert.Equal(32, XWingKem.X25519SharedSecretLength);
    }
}
