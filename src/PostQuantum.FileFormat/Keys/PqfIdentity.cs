namespace PostQuantum.FileFormat.Keys;

public sealed class PqfIdentity
{
    public PqfIdentity(PqfPublicKey publicKey)
    {
        PublicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
    }

    public PqfPublicKey PublicKey { get; }
}