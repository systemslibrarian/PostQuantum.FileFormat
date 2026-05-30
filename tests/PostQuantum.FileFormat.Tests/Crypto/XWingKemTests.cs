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

    [Fact]
    public void XWingCombiner_MatchesPublishedDraftVector()
    {
        // KAT against draft-connolly-cfrg-xwing-kem Appendix C, example 1.
        //
        // The X-Wing draft publishes (seed, eseed, pk, ct, ss) for a complete
        // deterministic encapsulation. The Rust KAT
        // (impl/rust/pqf-writer/tests/xwing_draft_kat.rs) replays the full
        // encap using ml-kem 0.2's deterministic feature + x25519-dalek and
        // proves the combiner output equals the published ss byte-for-byte.
        //
        // This .NET-side KAT covers the same property — that the SHA3-256
        // combiner formula is byte-correct against the draft — without
        // requiring deterministic ML-KEM encap on the .NET surface.
        // BouncyCastle 2.6.2 does not expose ML-KEM EncapsDerand publicly,
        // so we instead pin the four intermediate values the Rust KAT
        // surfaces (after independently verifying them against the draft)
        // and assert XWingKem.ComputeCombiner(those bytes) reproduces the
        // published ss.
        //
        // ct_X and pk_X are independently verifiable: they are the last 32
        // bytes of the draft's published ct (1120 bytes) and pk (1216 bytes)
        // respectively. The Rust KAT's pk hex / ct hex tail bytes match.
        //
        // If THIS assertion ever fails, exactly one of these has gone wrong:
        //   (a) the SHA3-256 input order in XWingKem.ComputeCombiner drifted
        //       (most likely the label position),
        //   (b) the XWING_LABEL constant drifted from 5C 2E 2F 2F 5E 5C,
        //   (c) BouncyCastle's Sha3Digest(256) diverged from FIPS 202, or
        //   (d) the draft's appendix vector changed.
        //
        // Reference: draft-connolly-cfrg-xwing-kem, Appendix C, example 1.

        var ssM = Convert.FromHexString(
            "7631eaf24bcc7ba2d1656d8f53778f8caa5f1ce33180e8ab405b9247eab76dfc");
        var ssX = Convert.FromHexString(
            "1e53cb26910141b4a09b0664deb8ec55376bcdbdfe2bfc8277883939a76d6131");
        var ctX = Convert.FromHexString(
            "e56f17576740ce2a32fc5145030145cfb97e63e0e41d354274a079d3e6fb2e15");
        var pkX = Convert.FromHexString(
            "859edb06eff389b27dce59844570216223593d4ba32d9abac8cd049040ef6534");
        var expectedSs = Convert.FromHexString(
            "d2df0522128f09dd8e2c92b1e905c793d8f57a54c3da25861f10bf4ca613e384");

        var computedSs = XWingKem.ComputeCombiner(ssM, ssX, ctX, pkX);

        Assert.Equal(expectedSs, computedSs);
    }
}
