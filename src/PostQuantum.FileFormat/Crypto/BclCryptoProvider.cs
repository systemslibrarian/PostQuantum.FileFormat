using System.Reflection;

namespace PostQuantum.FileFormat.Crypto;

/// <summary>
/// Crypto provider that prefers the .NET 10+ Base Class Library
/// implementations of ML-KEM and ML-DSA when they are available at runtime,
/// and falls back to BouncyCastle for everything else (X25519, Ed25519,
/// and ML-KEM/ML-DSA on runtimes that do not yet ship the BCL APIs).
///
/// All BCL access goes through reflection so the project keeps building on
/// the .NET 8 LTS target framework, which does not have these types at
/// compile time. The reflection plumbing is one-time at type-init; per-call
/// cost is a single MethodInfo.Invoke per primitive.
///
/// Why the BCL path matters for the side-channel posture:
/// BouncyCastle's managed ML-KEM and ML-DSA implementations are not written
/// to be constant-time; the BCL implementations are platform-backed and are
/// expected to provide stronger constant-time guarantees on the platforms
/// where System.Security.Cryptography.MLKem.IsSupported is true. See
/// docs/SIDE-CHANNEL-POSTURE.md for the full discussion.
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
/// Reflection bridge for System.Security.Cryptography.MLKem on .NET 10+.
/// Type-init reflects once and caches MethodInfo handles for the byte[]
/// overloads we use. Per-call cost is one Invoke per primitive.
/// </summary>
internal static class BclMlKemBridge
{
    private static readonly Type? _algorithmType = Type.GetType("System.Security.Cryptography.MLKemAlgorithm, System.Security.Cryptography");
    private static readonly Type? _mlKemType = Type.GetType("System.Security.Cryptography.MLKem, System.Security.Cryptography");

    private static readonly object? _mlKem768;
    private static readonly MethodInfo? _generateKey;
    private static readonly MethodInfo? _importEncapsulationKey;
    private static readonly MethodInfo? _importDecapsulationKey;
    private static readonly MethodInfo? _exportEncapsulationKey;
    private static readonly MethodInfo? _exportDecapsulationKey;
    private static readonly MethodInfo? _encapsulateOutOut;
    private static readonly MethodInfo? _decapsulateBytes;

    public static readonly bool MlKem768Supported;

    static BclMlKemBridge()
    {
        if (_mlKemType is null || _algorithmType is null) return;

        try
        {
            var mlKem768Prop = _algorithmType.GetProperty("MLKem768", BindingFlags.Public | BindingFlags.Static);
            _mlKem768 = mlKem768Prop?.GetValue(null);
            if (_mlKem768 is null) return;

            var isSupportedProp = _mlKemType.GetProperty("IsSupported", BindingFlags.Public | BindingFlags.Static);
            if (isSupportedProp?.GetValue(null) is not bool isSupported || !isSupported) return;

            _generateKey = _mlKemType.GetMethod("GenerateKey", BindingFlags.Public | BindingFlags.Static, binder: null, types: new[] { _algorithmType }, modifiers: null);
            _importEncapsulationKey = _mlKemType.GetMethod("ImportEncapsulationKey", BindingFlags.Public | BindingFlags.Static, binder: null, types: new[] { _algorithmType, typeof(byte[]) }, modifiers: null);
            _importDecapsulationKey = _mlKemType.GetMethod("ImportDecapsulationKey", BindingFlags.Public | BindingFlags.Static, binder: null, types: new[] { _algorithmType, typeof(byte[]) }, modifiers: null);
            _exportEncapsulationKey = _mlKemType.GetMethod("ExportEncapsulationKey", BindingFlags.Public | BindingFlags.Instance, binder: null, types: Type.EmptyTypes, modifiers: null);
            _exportDecapsulationKey = _mlKemType.GetMethod("ExportDecapsulationKey", BindingFlags.Public | BindingFlags.Instance, binder: null, types: Type.EmptyTypes, modifiers: null);
            _encapsulateOutOut = _mlKemType.GetMethod("Encapsulate", BindingFlags.Public | BindingFlags.Instance, binder: null, types: new[] { typeof(byte[]).MakeByRefType(), typeof(byte[]).MakeByRefType() }, modifiers: null);
            _decapsulateBytes = _mlKemType.GetMethod("Decapsulate", BindingFlags.Public | BindingFlags.Instance, binder: null, types: new[] { typeof(byte[]) }, modifiers: null);

            if (_generateKey is null || _importEncapsulationKey is null || _importDecapsulationKey is null
                || _exportEncapsulationKey is null || _exportDecapsulationKey is null
                || _encapsulateOutOut is null || _decapsulateBytes is null)
            {
                return;
            }

            // Liveness probe: actually generate-and-dispose a 768 key.
            using (_generateKey.Invoke(null, new[] { _mlKem768 }) as IDisposable)
            {
                MlKem768Supported = true;
            }
        }
        catch (TargetInvocationException tie) when (tie.InnerException is PlatformNotSupportedException)
        {
        }
        catch (PlatformNotSupportedException)
        {
        }
        catch
        {
            // Any other reflection failure: stay on BC fallback.
        }
    }

    public static (byte[] sk, byte[] pk) GenerateKeyPair()
    {
        var instance = _generateKey!.Invoke(null, new[] { _mlKem768 })!;
        try
        {
            var pk = (byte[])_exportEncapsulationKey!.Invoke(instance, null)!;
            var sk = (byte[])_exportDecapsulationKey!.Invoke(instance, null)!;
            return (sk, pk);
        }
        finally
        {
            (instance as IDisposable)?.Dispose();
        }
    }

    public static (byte[] sharedSecret, byte[] ciphertext) Encapsulate(ReadOnlySpan<byte> peerPk)
    {
        var pkBytes = peerPk.ToArray();
        var instance = _importEncapsulationKey!.Invoke(null, new object?[] { _mlKem768, pkBytes })!;
        try
        {
            var args = new object?[] { null, null };
            _encapsulateOutOut!.Invoke(instance, args);
            var ciphertext = (byte[])args[0]!;
            var secret = (byte[])args[1]!;
            return (secret, ciphertext);
        }
        finally
        {
            (instance as IDisposable)?.Dispose();
            SecureZero.Clear(pkBytes);
        }
    }

    public static byte[] Decapsulate(ReadOnlySpan<byte> sk, ReadOnlySpan<byte> ciphertext)
    {
        var skBytes = sk.ToArray();
        var ctBytes = ciphertext.ToArray();
        object? instance = null;
        try
        {
            instance = _importDecapsulationKey!.Invoke(null, new object?[] { _mlKem768, skBytes })!;
            return (byte[])_decapsulateBytes!.Invoke(instance, new object?[] { ctBytes })!;
        }
        finally
        {
            (instance as IDisposable)?.Dispose();
            SecureZero.Clear(skBytes);
            SecureZero.Clear(ctBytes);
        }
    }
}

/// <summary>
/// Reflection bridge for System.Security.Cryptography.MLDsa on .NET 10+.
/// Mirrors BclMlKemBridge's detection logic.
/// </summary>
internal static class BclMlDsaBridge
{
    private static readonly Type? _algorithmType = Type.GetType("System.Security.Cryptography.MLDsaAlgorithm, System.Security.Cryptography");
    private static readonly Type? _mlDsaType = Type.GetType("System.Security.Cryptography.MLDsa, System.Security.Cryptography");

    private static readonly object? _mlDsa87;
    private static readonly MethodInfo? _generateKey;
    private static readonly MethodInfo? _importPrivateKey;
    private static readonly MethodInfo? _importPublicKey;
    private static readonly MethodInfo? _exportPrivateKey;
    private static readonly MethodInfo? _exportPublicKey;
    private static readonly MethodInfo? _signDataBytes;
    private static readonly MethodInfo? _verifyDataBytes;

    public static readonly bool MlDsa87Supported;

    static BclMlDsaBridge()
    {
        if (_mlDsaType is null || _algorithmType is null) return;

        try
        {
            var mlDsa87Prop = _algorithmType.GetProperty("MLDsa87", BindingFlags.Public | BindingFlags.Static);
            _mlDsa87 = mlDsa87Prop?.GetValue(null);
            if (_mlDsa87 is null) return;

            var isSupportedProp = _mlDsaType.GetProperty("IsSupported", BindingFlags.Public | BindingFlags.Static);
            if (isSupportedProp?.GetValue(null) is not bool isSupported || !isSupported) return;

            _generateKey = _mlDsaType.GetMethod("GenerateKey", BindingFlags.Public | BindingFlags.Static, binder: null, types: new[] { _algorithmType }, modifiers: null);
            _importPrivateKey = _mlDsaType.GetMethod("ImportMLDsaPrivateKey", BindingFlags.Public | BindingFlags.Static, binder: null, types: new[] { _algorithmType, typeof(byte[]) }, modifiers: null);
            _importPublicKey = _mlDsaType.GetMethod("ImportMLDsaPublicKey", BindingFlags.Public | BindingFlags.Static, binder: null, types: new[] { _algorithmType, typeof(byte[]) }, modifiers: null);
            _exportPrivateKey = _mlDsaType.GetMethod("ExportMLDsaPrivateKey", BindingFlags.Public | BindingFlags.Instance, binder: null, types: Type.EmptyTypes, modifiers: null);
            _exportPublicKey = _mlDsaType.GetMethod("ExportMLDsaPublicKey", BindingFlags.Public | BindingFlags.Instance, binder: null, types: Type.EmptyTypes, modifiers: null);
            _signDataBytes = _mlDsaType.GetMethod("SignData", BindingFlags.Public | BindingFlags.Instance, binder: null, types: new[] { typeof(byte[]), typeof(byte[]) }, modifiers: null);
            _verifyDataBytes = _mlDsaType.GetMethod("VerifyData", BindingFlags.Public | BindingFlags.Instance, binder: null, types: new[] { typeof(byte[]), typeof(byte[]), typeof(byte[]) }, modifiers: null);

            if (_generateKey is null || _importPrivateKey is null || _importPublicKey is null
                || _exportPrivateKey is null || _exportPublicKey is null
                || _signDataBytes is null || _verifyDataBytes is null)
            {
                return;
            }

            using (_generateKey.Invoke(null, new[] { _mlDsa87 }) as IDisposable)
            {
                MlDsa87Supported = true;
            }
        }
        catch (TargetInvocationException tie) when (tie.InnerException is PlatformNotSupportedException)
        {
        }
        catch (PlatformNotSupportedException)
        {
        }
        catch
        {
        }
    }

    public static (byte[] sk, byte[] pk) GenerateKeyPair()
    {
        var instance = _generateKey!.Invoke(null, new[] { _mlDsa87 })!;
        try
        {
            var pk = (byte[])_exportPublicKey!.Invoke(instance, null)!;
            var sk = (byte[])_exportPrivateKey!.Invoke(instance, null)!;
            return (sk, pk);
        }
        finally
        {
            (instance as IDisposable)?.Dispose();
        }
    }

    public static byte[] Sign(ReadOnlySpan<byte> sk, ReadOnlySpan<byte> message)
    {
        var skBytes = sk.ToArray();
        var msgBytes = message.ToArray();
        object? instance = null;
        try
        {
            instance = _importPrivateKey!.Invoke(null, new object?[] { _mlDsa87, skBytes })!;
            // Empty context per the PQF spec (ML-DSA used without a context string).
            return (byte[])_signDataBytes!.Invoke(instance, new object?[] { msgBytes, Array.Empty<byte>() })!;
        }
        finally
        {
            (instance as IDisposable)?.Dispose();
            SecureZero.Clear(skBytes);
            SecureZero.Clear(msgBytes);
        }
    }

    public static bool Verify(ReadOnlySpan<byte> pk, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
    {
        var pkBytes = pk.ToArray();
        var msgBytes = message.ToArray();
        var sigBytes = signature.ToArray();
        object? instance = null;
        try
        {
            instance = _importPublicKey!.Invoke(null, new object?[] { _mlDsa87, pkBytes })!;
            return (bool)_verifyDataBytes!.Invoke(instance, new object?[] { msgBytes, sigBytes, Array.Empty<byte>() })!;
        }
        catch (TargetInvocationException)
        {
            // BCL throws on malformed inputs; treat as verify-fail to match
            // the BouncyCastle path's swallow-and-return-false behaviour.
            return false;
        }
        finally
        {
            (instance as IDisposable)?.Dispose();
            SecureZero.Clear(pkBytes);
            SecureZero.Clear(msgBytes);
            SecureZero.Clear(sigBytes);
        }
    }
}
