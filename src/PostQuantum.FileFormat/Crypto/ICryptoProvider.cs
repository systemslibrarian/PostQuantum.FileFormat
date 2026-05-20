namespace PostQuantum.FileFormat.Crypto;

public interface ICryptoProvider
{
    (byte[] sk, byte[] pk) X25519GenerateKeyPair();
    byte[] X25519DeriveSharedSecret(ReadOnlySpan<byte> sk, ReadOnlySpan<byte> peerPk);

    (byte[] sk, byte[] pk) MlKem1024GenerateKeyPair();
    (byte[] sharedSecret, byte[] ciphertext) MlKem1024Encapsulate(ReadOnlySpan<byte> peerPk);
    byte[] MlKem1024Decapsulate(ReadOnlySpan<byte> sk, ReadOnlySpan<byte> ciphertext);

    (byte[] sk, byte[] pk) Ed25519GenerateKeyPair();
    byte[] Ed25519Sign(ReadOnlySpan<byte> sk, ReadOnlySpan<byte> message);
    bool Ed25519Verify(ReadOnlySpan<byte> pk, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature);

    (byte[] sk, byte[] pk) MlDsa87GenerateKeyPair();
    byte[] MlDsa87Sign(ReadOnlySpan<byte> sk, ReadOnlySpan<byte> message);
    bool MlDsa87Verify(ReadOnlySpan<byte> pk, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature);

    /// <summary>
    /// FIPS 204 deterministic-signing variant: the per-signature rnd is the
    /// all-zero byte string, so two signatures over the same message under
    /// the same key are byte-identical. Used for byte-deterministic test
    /// vector regeneration and for callers that explicitly want
    /// repeatability (e.g. transparency log entries). The default
    /// implementation forwards to <see cref="MlDsa87Sign"/>; providers
    /// that support FIPS 204 deterministic signing should override.
    /// </summary>
    byte[] MlDsa87SignDeterministic(ReadOnlySpan<byte> sk, ReadOnlySpan<byte> message)
        => MlDsa87Sign(sk, message);
}
