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
        => SignCore(identity, message, deterministic: false);

    /// <summary>
    /// Hybrid sign using FIPS 204 deterministic ML-DSA-87 (rnd = 0).
    /// Ed25519 is already deterministic per RFC 8032 §5.1.6, so the full
    /// hybrid signature is byte-identical across runs for the same
    /// (signing-identity, message) pair. Used for byte-deterministic test
    /// vector regeneration; not the recommended default for new files.
    /// </summary>
    public byte[] SignDeterministic(PqfSigningIdentity identity, ReadOnlySpan<byte> message)
        => SignCore(identity, message, deterministic: true);

    private byte[] SignCore(PqfSigningIdentity identity, ReadOnlySpan<byte> message, bool deterministic)
    {
        var edSig = _provider.Ed25519Sign(identity.Ed25519PrivateKey.Span, message);
        var pqSig = deterministic
            ? _provider.MlDsa87SignDeterministic(identity.MlDsa87PrivateKey.Span, message)
            : _provider.MlDsa87Sign(identity.MlDsa87PrivateKey.Span, message);

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

        // Both halves are always evaluated. Using bitwise & rather than the
        // short-circuit && means a timing observer cannot distinguish
        // "Ed25519 failed" from "Ed25519 passed but ML-DSA-87 failed" by the
        // wall-clock cost of the call. The file is refused either way; this is
        // defense in depth against a leak the underlying primitives might add.
        var classicalOk = _provider.Ed25519Verify(publicKey.Ed25519PublicKey.Span, message, signature[..64]);
        var pqcOk = _provider.MlDsa87Verify(publicKey.MlDsa87PublicKey.Span, message, signature[64..]);
        return classicalOk & pqcOk;
    }
}
