using PostQuantum.FileFormat.Keys;
using System.Security.Cryptography;

namespace PostQuantum.FileFormat.Crypto;

public sealed class HybridSigner
{
    public const int HybridSignatureLength = 4691;

    private readonly ICryptoProvider _provider;

    public HybridSigner(ICryptoProvider provider)
    {
        _provider = provider;
    }

    public byte[] Sign(PqfSigningIdentity identity, ReadOnlySpan<byte> message)
    {
        var edSig = _provider.Ed25519Sign(identity.Ed25519PrivateKey.Span, message);
        var pqSig = _provider.MlDsa87Sign(identity.MlDsa87PrivateKey.Span, message);

        if (edSig.Length != 64 || pqSig.Length != 4627)
        {
            throw new CryptographicException("Hybrid signature component lengths do not match spec");
        }

        var signature = new byte[HybridSignatureLength];
        edSig.CopyTo(signature, 0);
        pqSig.CopyTo(signature, 64);

        return signature;
    }

    public bool Verify(
        PqfSigningPublicKey publicKey,
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> signature)
    {
        if (signature.Length != HybridSignatureLength)
        {
            return false;
        }

        var classicalOk = _provider.Ed25519Verify(publicKey.Ed25519PublicKey.Span, message, signature[..64]);
        var pqcOk = _provider.MlDsa87Verify(publicKey.MlDsa87PublicKey.Span, message, signature[64..]);
        return classicalOk && pqcOk;
    }
}
