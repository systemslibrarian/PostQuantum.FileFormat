using PostQuantum.FileFormat.Keys;

namespace PostQuantum.FileFormat.File;

public static class PqfFile
{
    public static Task EncryptAsync(
        Stream plaintext,
        Stream destination,
        IReadOnlyList<PqfPublicKey> recipients,
        PqfSigningIdentity? signer,
        int chunkSize = 65536,
        CancellationToken cancellationToken = default)
    {
        return PqfFileWriter.EncryptAsync(plaintext, destination, recipients, signer, chunkSize, provider: null, cancellationToken);
    }
}
