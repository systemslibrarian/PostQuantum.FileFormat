using PostQuantum.FileFormat.File;
using PostQuantum.FileFormat.Keys;

namespace PostQuantum.FileFormat.Tests.File;

public sealed class StreamingModeTests
{
    [Fact]
    public async Task Streaming_mode_successful_roundtrip_returns_success_result()
    {
        using var identity = PqfIdentity.Generate();
        var plaintext = RandomBytes(120_000);

        using var encrypted = new MemoryStream();
        await PqfFileWriter.EncryptAsync(new MemoryStream(plaintext), encrypted, new[] { identity.PublicKey }, signer: null);

        encrypted.Position = 0;
        using var decrypted = new MemoryStream();
        var result = await PqfDecryptor.DecryptStreamingAsync(encrypted, decrypted, identity);

        Assert.True(result.Success);
        Assert.False(result.PostHocAuthenticationFailed);
        Assert.Equal(plaintext.LongLength, result.PlaintextBytesEmitted);
        Assert.Equal(plaintext, decrypted.ToArray());
    }

    [Fact]
    public async Task Streaming_mode_reports_posthoc_failure_for_tampered_file_signature()
    {
        using var identity = PqfIdentity.Generate();
        using var signer = PqfSigningIdentity.Generate();
        var plaintext = RandomBytes(90_000);

        using var encrypted = new MemoryStream();
        await PqfFileWriter.EncryptAsync(new MemoryStream(plaintext), encrypted, new[] { identity.PublicKey }, signer);

        var bytes = encrypted.ToArray();
        bytes[^1] ^= 0x01;

        using var tampered = new MemoryStream(bytes);
        using var decrypted = new MemoryStream();
        var result = await PqfDecryptor.DecryptStreamingAsync(tampered, decrypted, identity);

        Assert.False(result.Success);
        Assert.True(result.PostHocAuthenticationFailed);
        Assert.Equal(PqfRefusalReason.SignatureVerificationFailure, result.FailureReason);
        Assert.True(result.PlaintextBytesEmitted > 0);
        Assert.True(decrypted.Length > 0);
    }

    private static byte[] RandomBytes(int n)
    {
        var b = new byte[n];
        System.Security.Cryptography.RandomNumberGenerator.Fill(b);
        return b;
    }
}
