using Org.BouncyCastle.Crypto.Digests;

namespace PostQuantum.FileFormat.Crypto;

/// <summary>
/// X-Wing hybrid KEM combiner — draft-connolly-cfrg-xwing-kem.
///
/// Combines ML-KEM-768 (post-quantum) and X25519 (classical) into a single
/// 32-byte shared secret. Unlike the previous in-house HKDF combiner this
/// construction has external security proofs (Barbosa et al., 2024,
/// IND-CCA in ROM/QROM) and binds both the X25519 ephemeral public key and
/// the recipient X25519 public key into the KDF input, which the prior
/// PQF combiner did not.
///
/// Combiner formula:
///   ss = SHA3-256( ss_M || ss_X || ct_X || pk_X || XWING_LABEL )
/// where
///   XWING_LABEL is the 6-byte ASCII art "\.//^\" — bytes 5C 2E 2F 2F 5E 5C
///   ss_M        is the 32-byte ML-KEM-768 shared secret
///   ss_X        is the 32-byte X25519 shared secret
///   ct_X        is the 32-byte X25519 ephemeral public key (the "ciphertext")
///   pk_X        is the recipient's 32-byte X25519 long-term public key
///
/// The X-Wing ciphertext on the wire is ct_M || ct_X (1088 + 32 = 1120 bytes).
/// PQF transports ct_M and ct_X in separate header fields ("pqc_ct" and
/// "classical_epk") for backward continuity with the v1 header shape; the
/// combiner inputs are byte-identical to draft-connolly-cfrg-xwing-kem
/// regardless of wire packaging.
/// </summary>
public sealed class XWingKem
{
    /// <summary>
    /// X-Wing domain-separation label — six bytes forming the ASCII art
    /// "\.//^\". This is the literal byte sequence specified by the draft.
    /// It is NOT the ASCII string "X-Wing"; any implementation that uses
    /// "X-Wing" will derive a different shared secret and silently fail
    /// interop with conforming X-Wing implementations.
    /// </summary>
    public static ReadOnlySpan<byte> Label => new byte[] { 0x5C, 0x2E, 0x2F, 0x2F, 0x5E, 0x5C };

    public const int SharedSecretLength = 32;
    public const int MlKem768CiphertextLength = 1088;
    public const int X25519PublicKeyLength = 32;
    public const int MlKem768SharedSecretLength = 32;
    public const int X25519SharedSecretLength = 32;

    private readonly ICryptoProvider _provider;

    public XWingKem(ICryptoProvider provider)
    {
        _provider = provider ?? throw new ArgumentNullException(nameof(provider));
    }

    /// <summary>
    /// Encapsulate to a recipient. Returns the X25519 ephemeral public key
    /// (ct_X), the ML-KEM-768 ciphertext (ct_M), and the 32-byte X-Wing
    /// shared secret.
    /// </summary>
    public (byte[] classicalEpk, byte[] pqcCiphertext, byte[] sharedSecret) Encapsulate(
        ReadOnlySpan<byte> recipientMlKem768PublicKey,
        ReadOnlySpan<byte> recipientX25519PublicKey)
    {
        if (recipientX25519PublicKey.Length != X25519PublicKeyLength)
        {
            throw new ArgumentException($"X25519 public key must be {X25519PublicKeyLength} bytes", nameof(recipientX25519PublicKey));
        }

        var (esk, epk) = _provider.X25519GenerateKeyPair();
        byte[]? ssX = null;
        byte[]? ssM = null;
        byte[]? ctM = null;
        try
        {
            ssX = _provider.X25519DeriveSharedSecret(esk, recipientX25519PublicKey);
            (ssM, ctM) = _provider.MlKem768Encapsulate(recipientMlKem768PublicKey);

            var ss = ComputeCombiner(ssM, ssX, epk, recipientX25519PublicKey);
            return (epk, ctM, ss);
        }
        finally
        {
            SecureZero.Clear(esk);
            SecureZero.Clear(ssX);
            SecureZero.Clear(ssM);
        }
    }

    /// <summary>
    /// Decapsulate using the recipient's identity. Caller provides ct_X
    /// (classical_epk from the header) and ct_M (pqc_ct from the header)
    /// separately; the recipient's own X25519 public key is needed because
    /// it is part of the combiner input.
    /// </summary>
    public byte[] Decapsulate(
        ReadOnlySpan<byte> mlKem768PrivateKey,
        ReadOnlySpan<byte> x25519PrivateKey,
        ReadOnlySpan<byte> x25519PublicKey,
        ReadOnlySpan<byte> classicalEpk,
        ReadOnlySpan<byte> pqcCiphertext)
    {
        if (classicalEpk.Length != X25519PublicKeyLength)
        {
            throw new ArgumentException($"classical_epk must be {X25519PublicKeyLength} bytes", nameof(classicalEpk));
        }

        if (pqcCiphertext.Length != MlKem768CiphertextLength)
        {
            throw new ArgumentException($"pqc_ct must be {MlKem768CiphertextLength} bytes", nameof(pqcCiphertext));
        }

        if (x25519PublicKey.Length != X25519PublicKeyLength)
        {
            throw new ArgumentException($"X25519 public key must be {X25519PublicKeyLength} bytes", nameof(x25519PublicKey));
        }

        byte[]? ssX = null;
        byte[]? ssM = null;
        try
        {
            // ML-KEM decap MUST always run even on a malformed ciphertext,
            // returning a pseudorandom secret (FIPS 203 implicit rejection).
            // The caller's downstream AEAD failure is the only signal of a
            // wrong recipient — see spec §6.3 step 8b.
            ssM = _provider.MlKem768Decapsulate(mlKem768PrivateKey, pqcCiphertext);
            ssX = _provider.X25519DeriveSharedSecret(x25519PrivateKey, classicalEpk);
            return ComputeCombiner(ssM, ssX, classicalEpk, x25519PublicKey);
        }
        finally
        {
            SecureZero.Clear(ssM);
            SecureZero.Clear(ssX);
        }
    }

    // Exposed `internal` (rather than `private`) so that
    // `XWingKemTests.XWingCombiner_MatchesPublishedDraftVector` can drive
    // it with hard-coded intermediate values extracted from the X-Wing
    // draft Appendix C vector — the BouncyCastle 2.6.2 .NET surface does
    // not expose ML-KEM deterministic encap, so a full encap-driven KAT
    // is not feasible on the .NET side. The Rust KAT in
    // `impl/rust/pqf-writer/tests/xwing_draft_kat.rs` covers the full
    // encap path; this entry point covers the SHA3-256 invocation
    // independently. Production callers go through Encapsulate /
    // Decapsulate above.
    internal static byte[] ComputeCombiner(
        ReadOnlySpan<byte> ssM,
        ReadOnlySpan<byte> ssX,
        ReadOnlySpan<byte> ctX,
        ReadOnlySpan<byte> pkX)
    {
        if (ssM.Length != MlKem768SharedSecretLength)
        {
            throw new ArgumentException($"ss_M must be {MlKem768SharedSecretLength} bytes", nameof(ssM));
        }

        if (ssX.Length != X25519SharedSecretLength)
        {
            throw new ArgumentException($"ss_X must be {X25519SharedSecretLength} bytes", nameof(ssX));
        }

        if (ctX.Length != X25519PublicKeyLength)
        {
            throw new ArgumentException($"ct_X must be {X25519PublicKeyLength} bytes", nameof(ctX));
        }

        if (pkX.Length != X25519PublicKeyLength)
        {
            throw new ArgumentException($"pk_X must be {X25519PublicKeyLength} bytes", nameof(pkX));
        }

        var sha3 = new Sha3Digest(256);
        var label = Label;
        Span<byte> labelBuffer = stackalloc byte[6];
        label.CopyTo(labelBuffer);

        var ssMBuf = ssM.ToArray();
        var ssXBuf = ssX.ToArray();
        var ctXBuf = ctX.ToArray();
        var pkXBuf = pkX.ToArray();
        try
        {
            // Per draft-connolly-cfrg-xwing-kem the label is APPENDED
            // (concat(ss_M, ss_X, ct_X, pk_X, XWingLabel)), not prepended.
            // An earlier version of this code had the label first; the
            // X-Wing draft KAT in tests/xwing_draft_kat.rs caught the
            // discrepancy on 2026-05-30. Self-consistency tests would
            // not have noticed because both sides of every round-trip
            // used the wrong order.
            sha3.BlockUpdate(ssMBuf, 0, ssMBuf.Length);
            sha3.BlockUpdate(ssXBuf, 0, ssXBuf.Length);
            sha3.BlockUpdate(ctXBuf, 0, ctXBuf.Length);
            sha3.BlockUpdate(pkXBuf, 0, pkXBuf.Length);
            sha3.BlockUpdate(labelBuffer.ToArray(), 0, labelBuffer.Length);

            var output = new byte[SharedSecretLength];
            sha3.DoFinal(output, 0);
            return output;
        }
        finally
        {
            SecureZero.Clear(ssMBuf);
            SecureZero.Clear(ssXBuf);
            // ctX and pkX are non-secret but zero them anyway to match the
            // surrounding hygiene policy.
            SecureZero.Clear(ctXBuf);
            SecureZero.Clear(pkXBuf);
        }
    }
}
