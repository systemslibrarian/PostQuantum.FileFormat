using PostQuantum.FileFormat.Keys;
using System.Security.Cryptography;

namespace PostQuantum.FileFormat.Crypto;

public sealed class HybridSigner
{
    public const int HybridSignatureLength = 4691;

    // Domain-separation labels prepended to each signed message so that the
    // header signature and the file signature are over disjoint, explicitly
    // tagged inputs (spec §6.2). The same hybrid key signs both, so without
    // these prefixes the two signing contexts would be distinguished only by
    // the structural difference of their payloads. The prefix closes that
    // question by construction.
    public static readonly byte[] HeaderSignatureDomain = "PQF1-header-sig-v1"u8.ToArray();
    public static readonly byte[] FileSignatureDomain = "PQF1-file-sig-v1"u8.ToArray();

    private readonly ICryptoProvider _provider;

    public HybridSigner(ICryptoProvider provider)
    {
        _provider = provider;
    }

    public byte[] Sign(PqfSigningIdentity identity, ReadOnlySpan<byte> domain, ReadOnlySpan<byte> message)
        => SignCore(identity, domain, message, deterministic: false);

    /// <summary>
    /// Hybrid sign using FIPS 204 deterministic ML-DSA-87 (rnd = 0).
    /// Ed25519 is already deterministic per RFC 8032 §5.1.6, so the full
    /// hybrid signature is byte-identical across runs for the same
    /// (signing-identity, domain, message) tuple. Used for byte-deterministic
    /// test vector regeneration. This is test-only plumbing and must never be
    /// surfaced through production encryption APIs.
    /// </summary>
    internal byte[] SignDeterministic(PqfSigningIdentity identity, ReadOnlySpan<byte> domain, ReadOnlySpan<byte> message)
        => SignCore(identity, domain, message, deterministic: true);

    private byte[] SignCore(PqfSigningIdentity identity, ReadOnlySpan<byte> domain, ReadOnlySpan<byte> message, bool deterministic)
    {
        var domainSeparated = PrependDomain(domain, message);
        try
        {
            return SignBytes(identity, domainSeparated, deterministic);
        }
        finally
        {
            SecureZero.Clear(domainSeparated);
        }
    }

    private byte[] SignBytes(PqfSigningIdentity identity, ReadOnlySpan<byte> message, bool deterministic)
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
        ReadOnlySpan<byte> domain,
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> signature)
    {
        if (signature.Length != HybridSignatureLength)
        {
            return false;
        }

        var domainSeparated = PrependDomain(domain, message);

        // Both halves are always evaluated. Using bitwise & rather than the
        // short-circuit && means a timing observer cannot distinguish
        // "Ed25519 failed" from "Ed25519 passed but ML-DSA-87 failed" by the
        // wall-clock cost of the call. The file is refused either way; this is
        // defense in depth against a leak the underlying primitives might add.
        var classicalOk = _provider.Ed25519Verify(publicKey.Ed25519PublicKey.Span, domainSeparated, signature[..64]);
        var pqcOk = _provider.MlDsa87Verify(publicKey.MlDsa87PublicKey.Span, domainSeparated, signature[64..]);
        return classicalOk & pqcOk;
    }

    private static byte[] PrependDomain(ReadOnlySpan<byte> domain, ReadOnlySpan<byte> message)
    {
        var buffer = new byte[domain.Length + message.Length];
        domain.CopyTo(buffer);
        message.CopyTo(buffer.AsSpan(domain.Length));
        return buffer;
    }
}
