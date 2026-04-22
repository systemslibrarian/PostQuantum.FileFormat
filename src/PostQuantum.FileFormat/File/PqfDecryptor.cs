using PostQuantum.FileFormat.Crypto;
using PostQuantum.FileFormat.Keys;

namespace PostQuantum.FileFormat.File;

public static class PqfDecryptor
{
    public static Task DecryptAsync(
        Stream source,
        Stream destination,
        PqfIdentity identity,
        CancellationToken ct = default)
    {
        var provider = CryptoProvider.Detect();
        var decryptor = new AuthenticatedModeDecryptor();
        return decryptor.DecryptAsync(source, destination, identity, provider, ct);
    }

    [MustUseReturnValue]
    public static Task<PqfDecryptResult> DecryptStreamingAsync(
        Stream source,
        Stream destination,
        PqfIdentity identity,
        CancellationToken ct = default)
    {
        var provider = CryptoProvider.Detect();
        var decryptor = new StreamingModeDecryptor();
        return decryptor.DecryptAsync(source, destination, identity, provider, ct);
    }
}
