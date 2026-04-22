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
        var fileId = RandomBytes(16);

        var (epk, ct, kek1) = kem.Encapsulate(identity.PublicKey, fileId, 0);
        var kek2 = kem.Decapsulate(identity, epk, ct, fileId, 0);

        Assert.Equal(kek1, kek2);
        Assert.Equal(32, kek1.Length);
    }

    [Fact]
    public void Decapsulate_changes_with_file_id_and_recipient_index()
    {
        var provider = CryptoProvider.Detect();
        using var identity = PqfIdentity.Generate(provider);
        var kem = new HybridKem(provider);
        var fileId = RandomBytes(16);

        var (epk, ct, kek) = kem.Encapsulate(identity.PublicKey, fileId, 1);
        var wrongFile = kem.Decapsulate(identity, epk, ct, RandomBytes(16), 1);
        var wrongIdx = kem.Decapsulate(identity, epk, ct, fileId, 2);

        Assert.NotEqual(kek, wrongFile);
        Assert.NotEqual(kek, wrongIdx);
    }

    private static byte[] RandomBytes(int n)
    {
        var b = new byte[n];
        System.Security.Cryptography.RandomNumberGenerator.Fill(b);
        return b;
    }
}
