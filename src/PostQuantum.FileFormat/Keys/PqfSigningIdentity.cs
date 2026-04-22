using PostQuantum.FileFormat.Crypto;

namespace PostQuantum.FileFormat.Keys;

public sealed class PqfSigningIdentity : IDisposable
{
    private readonly byte[]? _ed25519PrivateKey;
    private readonly byte[]? _mlDsa87PrivateKey;

    public PqfSigningIdentity(PqfSigningPublicKey publicKey)
    {
        PublicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
    }

    public PqfSigningIdentity(
        PqfSigningPublicKey publicKey,
        ReadOnlySpan<byte> ed25519PrivateKey,
        ReadOnlySpan<byte> mlDsa87PrivateKey)
    {
        if (ed25519PrivateKey.Length != 32)
        {
            throw new KeyFormatException("Ed25519 private key must be exactly 32 bytes.");
        }

        if (mlDsa87PrivateKey.Length == 0)
        {
            throw new KeyFormatException("ML-DSA-87 private key cannot be empty.");
        }

        PublicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
        _ed25519PrivateKey = ed25519PrivateKey.ToArray();
        _mlDsa87PrivateKey = mlDsa87PrivateKey.ToArray();
    }

    public PqfSigningPublicKey PublicKey { get; }

    public ReadOnlyMemory<byte> Ed25519PrivateKey => _ed25519PrivateKey ?? Array.Empty<byte>();

    public ReadOnlyMemory<byte> MlDsa87PrivateKey => _mlDsa87PrivateKey ?? Array.Empty<byte>();

    public static PqfSigningIdentity Generate(ICryptoProvider? provider = null)
    {
        var crypto = provider ?? CryptoProvider.Detect();
        var (edSk, edPk) = crypto.Ed25519GenerateKeyPair();
        var (mlSk, mlPk) = crypto.MlDsa87GenerateKeyPair();
        var pub = PqfSigningPublicKey.FromParts(edPk, mlPk);
        return new PqfSigningIdentity(pub, edSk, mlSk);
    }

    public void Dispose()
    {
        SecureZero.Clear(_ed25519PrivateKey);
        SecureZero.Clear(_mlDsa87PrivateKey);
    }
}