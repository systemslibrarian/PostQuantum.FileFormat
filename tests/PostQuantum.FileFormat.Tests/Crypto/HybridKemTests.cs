using PostQuantum.FileFormat.Crypto;
using PostQuantum.FileFormat.Keys;

namespace PostQuantum.FileFormat.Tests.Crypto;

public sealed class HybridKemTests
{
    [Fact]
    public void Encapsulate_then_decapsulate_recovers_same_kek()
    {
        var provider = CryptoProvider.Detect();
        using var identity = PqfIdentity.Generate(provider);
        var kem = new HybridKem(provider);

        var (epk, ct, kek1) = kem.Encapsulate(identity.PublicKey);
        var kek2 = kem.Decapsulate(identity, epk, ct);

        Assert.Equal(kek1, kek2);
        Assert.Equal(32, kek1.Length);
    }

    [Fact]
    public void Distinct_encapsulations_produce_distinct_keks()
    {
        // X-Wing's KEM combiner produces a KEK that is bound to the X25519
        // ephemeral and the ML-KEM ciphertext. Two encapsulations to the
        // same recipient produce different KEKs because the X25519 esk
        // (and therefore ct_X) and the ML-KEM ct are freshly random.
        var provider = CryptoProvider.Detect();
        using var identity = PqfIdentity.Generate(provider);
        var kem = new HybridKem(provider);

        var (_, _, kekA) = kem.Encapsulate(identity.PublicKey);
        var (_, _, kekB) = kem.Encapsulate(identity.PublicKey);

        Assert.NotEqual(kekA, kekB);
    }

    [Fact]
    public void Decapsulate_with_wrong_classical_epk_yields_different_kek()
    {
        // X-Wing binds ct_X (the X25519 ephemeral pk) into the KDF input.
        // Swapping ct_X with random bytes diverges the X-Wing combiner output
        // even though ML-KEM implicit rejection means decap "succeeds".
        var provider = CryptoProvider.Detect();
        using var identity = PqfIdentity.Generate(provider);
        var kem = new HybridKem(provider);

        var (epk, ct, kek) = kem.Encapsulate(identity.PublicKey);
        var bogusEpk = RandomBytes(32);
        var wrongKek = kem.Decapsulate(identity, bogusEpk, ct);

        Assert.NotEqual(kek, wrongKek);
    }

    private static byte[] RandomBytes(int n)
    {
        var b = new byte[n];
        System.Security.Cryptography.RandomNumberGenerator.Fill(b);
        return b;
    }
}
