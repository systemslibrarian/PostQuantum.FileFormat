namespace PostQuantum.FileFormat.Crypto;

// .NET 8 build target: ML-KEM/ML-DSA built-in APIs are not compile-time available.
// This provider is exposed for parity with the spec and runtime detection, and
// delegates to the BouncyCastle implementation in this target.
public sealed class BclCryptoProvider : ICryptoProvider
{
    private readonly BouncyCastleCryptoProvider _inner = new();

    public static bool IsSupported => false;

    public (byte[] sk, byte[] pk) X25519GenerateKeyPair() => _inner.X25519GenerateKeyPair();

    public byte[] X25519DeriveSharedSecret(ReadOnlySpan<byte> sk, ReadOnlySpan<byte> peerPk) =>
        _inner.X25519DeriveSharedSecret(sk, peerPk);

    public (byte[] sk, byte[] pk) MlKem1024GenerateKeyPair() => _inner.MlKem1024GenerateKeyPair();

    public (byte[] sharedSecret, byte[] ciphertext) MlKem1024Encapsulate(ReadOnlySpan<byte> peerPk) =>
        _inner.MlKem1024Encapsulate(peerPk);

    public byte[] MlKem1024Decapsulate(ReadOnlySpan<byte> sk, ReadOnlySpan<byte> ciphertext) =>
        _inner.MlKem1024Decapsulate(sk, ciphertext);

    public (byte[] sk, byte[] pk) Ed25519GenerateKeyPair() => _inner.Ed25519GenerateKeyPair();

    public byte[] Ed25519Sign(ReadOnlySpan<byte> sk, ReadOnlySpan<byte> message) =>
        _inner.Ed25519Sign(sk, message);

    public bool Ed25519Verify(ReadOnlySpan<byte> pk, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature) =>
        _inner.Ed25519Verify(pk, message, signature);

    public (byte[] sk, byte[] pk) MlDsa87GenerateKeyPair() => _inner.MlDsa87GenerateKeyPair();

    public byte[] MlDsa87Sign(ReadOnlySpan<byte> sk, ReadOnlySpan<byte> message) =>
        _inner.MlDsa87Sign(sk, message);

    public bool MlDsa87Verify(ReadOnlySpan<byte> pk, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature) =>
        _inner.MlDsa87Verify(pk, message, signature);
}
