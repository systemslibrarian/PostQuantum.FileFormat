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
}
