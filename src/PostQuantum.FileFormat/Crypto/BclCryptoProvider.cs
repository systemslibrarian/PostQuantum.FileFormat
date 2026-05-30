using System.Security.Cryptography;

namespace PostQuantum.FileFormat.Crypto;

/// <summary>
/// Crypto provider that goes directly to the .NET 10 BCL native PQC
/// primitives (<c>System.Security.Cryptography.MLKem</c> /
/// <c>System.Security.Cryptography.MLDsa</c>) for ML-KEM-768 and
/// ML-DSA-87, and falls back to BouncyCastle for everything else
/// (X25519, Ed25519, and the FIPS 204 deterministic-signing path which
/// the BCL does not yet expose).
///
/// The previous reflection bridge that reached these types from a net8.0
/// build was removed in the same change that dropped the net8.0 target
/// frame. The decision rationale: no consumer ships against net8.0, the
/// reflection layer was strictly worse than a compile-time reference for
/// every reviewer who looked at it, and keeping it preserved the weakest
/// side-channel link in the project for no current upside.
///
/// Why the BCL native path matters for the side-channel posture:
/// BouncyCastle's managed ML-KEM and ML-DSA implementations are not
/// written to be constant-time; the BCL implementations are platform-
/// backed (Linux OpenSSL 3.5+ via libcrypto; Windows CNG on 11 /
/// Server 2025) and are expected to provide stronger constant-time
/// guarantees on the platforms where
/// <c>System.Security.Cryptography.MLKem.IsSupported</c> is true. See
/// <c>docs/SIDE-CHANNEL-POSTURE.md</c> for the full discussion.
/// </summary>
public sealed class BclCryptoProvider : ICryptoProvider
{
    private readonly BouncyCastleCryptoProvider _fallback = new();

    internal void SetInjectableRandomness(TestSupport.InjectableRandomness? randomness)
    {
        _fallback.SetInjectableRandomness(randomness);
    }

    public static bool IsSupported => BclMlKemBridge.MlKem768Supported || BclMlDsaBridge.MlDsa87Supported;

    public static bool MlKem768UsesBcl => BclMlKemBridge.MlKem768Supported;

    public static bool MlDsa87UsesBcl => BclMlDsaBridge.MlDsa87Supported;

    public (byte[] sk, byte[] pk) X25519GenerateKeyPair() => _fallback.X25519GenerateKeyPair();

    public byte[] X25519DeriveSharedSecret(ReadOnlySpan<byte> sk, ReadOnlySpan<byte> peerPk) =>
        _fallback.X25519DeriveSharedSecret(sk, peerPk);

    public (byte[] sk, byte[] pk) MlKem768GenerateKeyPair() =>
        BclMlKemBridge.MlKem768Supported
            ? BclMlKemBridge.GenerateKeyPair()
            : _fallback.MlKem768GenerateKeyPair();

    public (byte[] sharedSecret, byte[] ciphertext) MlKem768Encapsulate(ReadOnlySpan<byte> peerPk) =>
        BclMlKemBridge.MlKem768Supported
            ? BclMlKemBridge.Encapsulate(peerPk)
            : _fallback.MlKem768Encapsulate(peerPk);

    public byte[] MlKem768Decapsulate(ReadOnlySpan<byte> sk, ReadOnlySpan<byte> ciphertext) =>
        BclMlKemBridge.MlKem768Supported
            ? BclMlKemBridge.Decapsulate(sk, ciphertext)
            : _fallback.MlKem768Decapsulate(sk, ciphertext);

    public (byte[] sk, byte[] pk) Ed25519GenerateKeyPair() => _fallback.Ed25519GenerateKeyPair();

    public byte[] Ed25519Sign(ReadOnlySpan<byte> sk, ReadOnlySpan<byte> message) =>
        _fallback.Ed25519Sign(sk, message);

    public bool Ed25519Verify(ReadOnlySpan<byte> pk, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature) =>
        _fallback.Ed25519Verify(pk, message, signature);

    public (byte[] sk, byte[] pk) MlDsa87GenerateKeyPair() =>
        BclMlDsaBridge.MlDsa87Supported
            ? BclMlDsaBridge.GenerateKeyPair()
            : _fallback.MlDsa87GenerateKeyPair();

    public byte[] MlDsa87Sign(ReadOnlySpan<byte> sk, ReadOnlySpan<byte> message) =>
        BclMlDsaBridge.MlDsa87Supported
            ? BclMlDsaBridge.Sign(sk, message)
            : _fallback.MlDsa87Sign(sk, message);

    // Deterministic FIPS 204 signing path. The .NET BCL MLDsa surface does
    // not currently expose an "rnd = 0" knob in a stable API, so we always
    // delegate to the BouncyCastle fallback for this path. Deterministic
    // signing is used for vector regeneration and explicit-repeatability
    // callers; both are fine with the BC backend.
    public byte[] MlDsa87SignDeterministic(ReadOnlySpan<byte> sk, ReadOnlySpan<byte> message) =>
        _fallback.MlDsa87SignDeterministic(sk, message);

    public bool MlDsa87Verify(ReadOnlySpan<byte> pk, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature) =>
        BclMlDsaBridge.MlDsa87Supported
            ? BclMlDsaBridge.Verify(pk, message, signature)
            : _fallback.MlDsa87Verify(pk, message, signature);
}

/// <summary>
/// Thin compile-time wrapper around
/// <c>System.Security.Cryptography.MLKem</c> (ML-KEM-768).
/// </summary>
internal static class BclMlKemBridge
{
    public static bool MlKem768Supported { get; } = ProbeSupported();

    private static bool ProbeSupported()
    {
        if (!MLKem.IsSupported)
        {
            return false;
        }
        // Liveness probe: actually generate-and-dispose a 768 key. Catches
        // the case where MLKem is exposed at compile time but the platform
        // provider does not support the parameter set at runtime.
        try
        {
            using var _ = MLKem.GenerateKey(MLKemAlgorithm.MLKem768);
            return true;
        }
        catch (PlatformNotSupportedException)
        {
            return false;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    public static (byte[] sk, byte[] pk) GenerateKeyPair()
    {
        using var instance = MLKem.GenerateKey(MLKemAlgorithm.MLKem768);
        var pk = instance.ExportEncapsulationKey();
        var sk = instance.ExportDecapsulationKey();
        return (sk, pk);
    }

    public static (byte[] sharedSecret, byte[] ciphertext) Encapsulate(ReadOnlySpan<byte> peerPk)
    {
        var pkBytes = peerPk.ToArray();
        using var instance = MLKem.ImportEncapsulationKey(MLKemAlgorithm.MLKem768, pkBytes);
        try
        {
            var ct = new byte[MLKemAlgorithm.MLKem768.CiphertextSizeInBytes];
            var ss = new byte[MLKemAlgorithm.MLKem768.SharedSecretSizeInBytes];
            instance.Encapsulate(ct, ss);
            return (ss, ct);
        }
        finally
        {
            SecureZero.Clear(pkBytes);
        }
    }

    public static byte[] Decapsulate(ReadOnlySpan<byte> sk, ReadOnlySpan<byte> ciphertext)
    {
        var skBytes = sk.ToArray();
        var ctBytes = ciphertext.ToArray();
        try
        {
            using var instance = MLKem.ImportDecapsulationKey(MLKemAlgorithm.MLKem768, skBytes);
            return instance.Decapsulate(ctBytes);
        }
        finally
        {
            SecureZero.Clear(skBytes);
            SecureZero.Clear(ctBytes);
        }
    }
}

/// <summary>
/// Thin compile-time wrapper around
/// <c>System.Security.Cryptography.MLDsa</c> (ML-DSA-87).
/// </summary>
internal static class BclMlDsaBridge
{
    public static bool MlDsa87Supported { get; } = ProbeSupported();

    private static bool ProbeSupported()
    {
        if (!MLDsa.IsSupported)
        {
            return false;
        }
        try
        {
            using var _ = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa87);
            return true;
        }
        catch (PlatformNotSupportedException)
        {
            return false;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    public static (byte[] sk, byte[] pk) GenerateKeyPair()
    {
        using var instance = MLDsa.GenerateKey(MLDsaAlgorithm.MLDsa87);
        var pk = instance.ExportMLDsaPublicKey();
        var sk = instance.ExportMLDsaPrivateKey();
        return (sk, pk);
    }

    public static byte[] Sign(ReadOnlySpan<byte> sk, ReadOnlySpan<byte> message)
    {
        var skBytes = sk.ToArray();
        var msgBytes = message.ToArray();
        try
        {
            using var instance = MLDsa.ImportMLDsaPrivateKey(MLDsaAlgorithm.MLDsa87, skBytes);
            // Empty context per the PQF spec (ML-DSA used without a context string).
            return instance.SignData(msgBytes, Array.Empty<byte>());
        }
        finally
        {
            SecureZero.Clear(skBytes);
            SecureZero.Clear(msgBytes);
        }
    }

    public static bool Verify(ReadOnlySpan<byte> pk, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
    {
        var pkBytes = pk.ToArray();
        var msgBytes = message.ToArray();
        var sigBytes = signature.ToArray();
        try
        {
            using var instance = MLDsa.ImportMLDsaPublicKey(MLDsaAlgorithm.MLDsa87, pkBytes);
            return instance.VerifyData(msgBytes, sigBytes, Array.Empty<byte>());
        }
        catch (CryptographicException)
        {
            // BCL throws on malformed inputs; treat as verify-fail to match
            // the BouncyCastle path's swallow-and-return-false behaviour.
            return false;
        }
        finally
        {
            SecureZero.Clear(pkBytes);
            SecureZero.Clear(msgBytes);
            SecureZero.Clear(sigBytes);
        }
    }
}
