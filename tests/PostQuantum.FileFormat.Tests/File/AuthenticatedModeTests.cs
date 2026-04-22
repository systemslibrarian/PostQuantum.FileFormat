using PostQuantum.FileFormat.File;
using PostQuantum.FileFormat.Keys;

namespace PostQuantum.FileFormat.Tests.File;

public sealed class AuthenticatedModeTests
{
    [Fact]
    public async Task Authenticated_mode_roundtrip_succeeds()
    {
        using var identity = PqfIdentity.Generate();
        var plaintext = RandomBytes(200_000);

        using var encrypted = new MemoryStream();
        await PqfFileWriter.EncryptAsync(new MemoryStream(plaintext), encrypted, new[] { identity.PublicKey }, signer: null);

        encrypted.Position = 0;
        using var decrypted = new MemoryStream();
        await PqfDecryptor.DecryptAsync(encrypted, decrypted, identity);

        Assert.Equal(plaintext, decrypted.ToArray());
    }

    [Fact]
    public async Task Authenticated_mode_writes_zero_bytes_on_signature_failure()
    {
        using var identity = PqfIdentity.Generate();
        using var signer = PqfSigningIdentity.Generate();
        var plaintext = RandomBytes(64_000);

        using var encrypted = new MemoryStream();
        await PqfFileWriter.EncryptAsync(new MemoryStream(plaintext), encrypted, new[] { identity.PublicKey }, signer);

        var bytes = encrypted.ToArray();
        bytes[^1] ^= 0x01; // Tamper file signature.

        using var tampered = new MemoryStream(bytes);
        using var decrypted = new MemoryStream();
        var ex = await Assert.ThrowsAsync<PqfFileException>(() => PqfDecryptor.DecryptAsync(tampered, decrypted, identity));

        Assert.Equal(PqfRefusalReason.SignatureVerificationFailure, ex.Reason);
        Assert.Equal(0, decrypted.Length);
    }

    private static byte[] RandomBytes(int n)
    {
        var b = new byte[n];
        System.Security.Cryptography.RandomNumberGenerator.Fill(b);
        return b;
    }
}
