using PostQuantum.FileFormat.Keys;

namespace PostQuantum.FileFormat.Crypto;

/// <summary>
/// PQF's hybrid encapsulation surface. Internally delegates to
/// <see cref="XWingKem"/> (draft-connolly-cfrg-xwing-kem), which combines
/// ML-KEM-768 and X25519 into a 32-byte shared secret with proven IND-CCA
/// security in ROM/QROM.
///
/// Per-file and per-recipient binding (file_id, recipient_index) does NOT
/// live in this layer — X-Wing's combiner has no salt slot. Those bindings
/// move into the DEK-wrap AEAD's associated data; see
/// <see cref="DekWrapper"/>.
/// </summary>
public sealed class HybridKem
{
    private readonly XWingKem _xwing;

    public HybridKem(ICryptoProvider provider)
    {
        _xwing = new XWingKem(provider);
    }

    public (byte[] classicalEpk, byte[] pqcCiphertext, byte[] kek) Encapsulate(
        PqfPublicKey recipientPublicKey)
    {
        if (recipientPublicKey is null) throw new ArgumentNullException(nameof(recipientPublicKey));
        return _xwing.Encapsulate(
            recipientPublicKey.MlKem768PublicKey.Span,
            recipientPublicKey.X25519PublicKey.Span);
    }

    public byte[] Decapsulate(
        PqfIdentity identity,
        ReadOnlySpan<byte> classicalEpk,
        ReadOnlySpan<byte> pqcCiphertext)
    {
        if (identity is null) throw new ArgumentNullException(nameof(identity));
        return _xwing.Decapsulate(
            identity.MlKem768PrivateKey.Span,
            identity.X25519PrivateKey.Span,
            identity.PublicKey.X25519PublicKey.Span,
            classicalEpk,
            pqcCiphertext);
    }
}
