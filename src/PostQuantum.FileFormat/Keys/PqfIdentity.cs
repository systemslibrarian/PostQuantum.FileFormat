using PostQuantum.FileFormat.Crypto;

namespace PostQuantum.FileFormat.Keys;

public sealed class PqfIdentity : IDisposable
{
    private readonly byte[]? _x25519PrivateKey;
    private readonly byte[]? _mlKem768PrivateKey;

    public PqfIdentity(PqfPublicKey publicKey)
    {
        PublicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
    }

    public PqfIdentity(
        PqfPublicKey publicKey,
        ReadOnlySpan<byte> x25519PrivateKey,
        ReadOnlySpan<byte> mlKem768PrivateKey)
    {
        if (x25519PrivateKey.Length != 32)
        {
            throw new KeyFormatException("X25519 private key must be exactly 32 bytes.");
        }

        if (mlKem768PrivateKey.Length == 0)
        {
            throw new KeyFormatException("ML-KEM-768 private key cannot be empty.");
        }

        PublicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
        _x25519PrivateKey = x25519PrivateKey.ToArray();
        _mlKem768PrivateKey = mlKem768PrivateKey.ToArray();
    }

    public PqfPublicKey PublicKey { get; }

    public ReadOnlyMemory<byte> X25519PrivateKey => _x25519PrivateKey ?? Array.Empty<byte>();

    public ReadOnlyMemory<byte> MlKem768PrivateKey => _mlKem768PrivateKey ?? Array.Empty<byte>();

    public static PqfIdentity Generate(ICryptoProvider? provider = null)
    {
        var crypto = provider ?? CryptoProvider.Detect();
        var (xSk, xPk) = crypto.X25519GenerateKeyPair();
        var (mlSk, mlPk) = crypto.MlKem768GenerateKeyPair();
        var pub = PqfPublicKey.FromParts(xPk, mlPk);
        return new PqfIdentity(pub, xSk, mlSk);
    }

    public void Dispose()
    {
        SecureZero.Clear(_x25519PrivateKey);
        SecureZero.Clear(_mlKem768PrivateKey);
    }
}
