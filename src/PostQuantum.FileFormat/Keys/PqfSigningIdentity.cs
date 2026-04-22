namespace PostQuantum.FileFormat.Keys;

public sealed class PqfSigningIdentity
{
    public PqfSigningIdentity(PqfSigningPublicKey publicKey)
    {
        PublicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
    }

    public PqfSigningPublicKey PublicKey { get; }
}