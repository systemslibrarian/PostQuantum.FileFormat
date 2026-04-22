using PostQuantum.FileFormat.Keys;

namespace PostQuantum.FileFormat.Crypto;

public sealed class HybridKem
{
    private readonly ICryptoProvider _provider;

    public HybridKem(ICryptoProvider provider)
    {
        _provider = provider;
    }

    public (byte[] classicalEpk, byte[] pqcCiphertext, byte[] kek) Encapsulate(
        PqfPublicKey recipientPublicKey,
        ReadOnlySpan<byte> fileId,
        uint recipientIndex)
    {
        var (esk, epk) = _provider.X25519GenerateKeyPair();
        var ssClassical = _provider.X25519DeriveSharedSecret(esk, recipientPublicKey.X25519PublicKey.Span);
        var (ssPqc, ctPqc) = _provider.MlKem1024Encapsulate(recipientPublicKey.MlKem1024PublicKey.Span);

        var kek = HkdfCombiner.DeriveKek(ssClassical, ssPqc, fileId, recipientIndex);

        SecureZero.Clear(esk);
        SecureZero.Clear(ssClassical);
        SecureZero.Clear(ssPqc);

        return (epk, ctPqc, kek);
    }

    public byte[] Decapsulate(
        PqfIdentity identity,
        ReadOnlySpan<byte> classicalEpk,
        ReadOnlySpan<byte> pqcCiphertext,
        ReadOnlySpan<byte> fileId,
        uint recipientIndex)
    {
        var ssClassical = _provider.X25519DeriveSharedSecret(identity.X25519PrivateKey.Span, classicalEpk);
        var ssPqc = _provider.MlKem1024Decapsulate(identity.MlKem1024PrivateKey.Span, pqcCiphertext);

        var kek = HkdfCombiner.DeriveKek(ssClassical, ssPqc, fileId, recipientIndex);

        SecureZero.Clear(ssClassical);
        SecureZero.Clear(ssPqc);

        return kek;
    }
}
