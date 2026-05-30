using System.IO;
using System.Threading.Tasks;
using PostQuantum.FileFormat.Crypto;
using PostQuantum.FileFormat.File;
using PostQuantum.FileFormat.Keys;

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

        // BCL-generated key, BC encapsulates, BCL decapsulates: shared secrets
        // must match. This is the operational path that proves the two stacks
        // produce wire-compatible ML-KEM outputs.
        var (sk, pk) = bcl.MlKem768GenerateKeyPair();
        var (ss1, ct) = bc.MlKem768Encapsulate(pk);
        var ss2 = bcl.MlKem768Decapsulate(sk, ct);

        Assert.Equal(ss1, ss2);

        // Reverse direction: BC-generated key, BCL encapsulates, BC decapsulates.
        var (sk2, pk2) = bc.MlKem768GenerateKeyPair();
        var (ss3, ct2) = bcl.MlKem768Encapsulate(pk2);
        var ss4 = bc.MlKem768Decapsulate(sk2, ct2);
        Assert.Equal(ss3, ss4);
    }

    [Fact]
    public void MlDsa_cross_provider_parity_when_bcl_supported()
    {
        if (!BclCryptoProvider.IsSupported)
        {
            return;
        }

        var bcl = new BclCryptoProvider();
        var bc = new BouncyCastleCryptoProvider();

        // BCL signs, BC verifies.
        var (sk, pk) = bcl.MlDsa87GenerateKeyPair();
        var msg = System.Text.Encoding.UTF8.GetBytes("PQF cross-provider ML-DSA test");
        var sig = bcl.MlDsa87Sign(sk, msg);
        Assert.True(bc.MlDsa87Verify(pk, msg, sig), "BC failed to verify a BCL-produced ML-DSA signature");

        // BC signs, BCL verifies.
        var (sk2, pk2) = bc.MlDsa87GenerateKeyPair();
        var sig2 = bc.MlDsa87Sign(sk2, msg);
        Assert.True(bcl.MlDsa87Verify(pk2, msg, sig2), "BCL failed to verify a BC-produced ML-DSA signature");
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

    [Fact]
    public async Task Bcl_provider_can_round_trip_full_pqf_file_when_supported()
    {
        // End-to-end test that the BCL-backed provider is wire-compatible:
        // generate keys with BCL, encrypt with BCL, decrypt with BCL, and
        // also decrypt with the BC fallback to prove the file is portable
        // across providers.
        if (!BclCryptoProvider.IsSupported)
        {
            return;
        }

        var bcl = new BclCryptoProvider();
        var bc = new BouncyCastleCryptoProvider();

        using var identity = PqfIdentity.Generate(bcl);
        using var signer = PqfSigningIdentity.Generate(bcl);

        var plaintext = new byte[37_000];
        new Random(0xC0DE).NextBytes(plaintext);

        using var src = new MemoryStream(plaintext);
        using var encrypted = new MemoryStream();
        await PqfFileWriter.EncryptAsync(
            src,
            encrypted,
            new[] { identity.PublicKey },
            signer,
            chunkSize: 8192,
            provider: bcl);

        encrypted.Position = 0;
        using var decryptedBcl = new MemoryStream();
        await PqfFileReader.DecryptAsync(encrypted, decryptedBcl, identity, bcl);
        Assert.Equal(plaintext, decryptedBcl.ToArray());

        encrypted.Position = 0;
        using var decryptedBc = new MemoryStream();
        await PqfFileReader.DecryptAsync(encrypted, decryptedBc, identity, bc);
        Assert.Equal(plaintext, decryptedBc.ToArray());
    }

    [Fact]
    public void Bcl_provider_tracks_platform_mlkem_support()
    {
        // If the running BCL exposes a usable System.Security.Cryptography.MLKem
        // (i.e. it's present AND MLKem.IsSupported is true), then our
        // reflection bridge must surface that as BclCryptoProvider.IsSupported.
        // On runtimes/platforms where MLKem isn't available, both should be
        // false and the BC fallback is used.
        var mlKemType = System.Type.GetType(
            "System.Security.Cryptography.MLKem, System.Security.Cryptography");
        if (mlKemType is null)
        {
            // Pre-.NET-10 runtime: types don't exist. Bridge must report not-supported.
            Assert.False(BclCryptoProvider.MlKem768UsesBcl);
            return;
        }

        var isSupportedProp = mlKemType.GetProperty(
            "IsSupported",
            System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static);
        var platformSupports = isSupportedProp?.GetValue(null) as bool? ?? false;

        Assert.Equal(platformSupports, BclCryptoProvider.MlKem768UsesBcl);
    }
}
