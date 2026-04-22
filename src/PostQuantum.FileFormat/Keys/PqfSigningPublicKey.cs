namespace PostQuantum.FileFormat.Keys;

public sealed class PqfSigningPublicKey
{
    public const int CanonicalByteLength = 2625;
    public const byte Version = 0x01;

    private const int Ed25519Length = 32;
    private const int MlDsa87Length = 2592;

    private readonly byte[] _ed25519PublicKey;
    private readonly byte[] _mlDsa87PublicKey;

    private PqfSigningPublicKey(byte versionByte, byte[] ed25519PublicKey, byte[] mlDsa87PublicKey)
    {
        VersionByte = versionByte;
        _ed25519PublicKey = ed25519PublicKey;
        _mlDsa87PublicKey = mlDsa87PublicKey;
    }

    public byte VersionByte { get; }

    public ReadOnlyMemory<byte> Ed25519PublicKey => _ed25519PublicKey.AsMemory();

    public ReadOnlyMemory<byte> MlDsa87PublicKey => _mlDsa87PublicKey.AsMemory();

    public static PqfSigningPublicKey FromCanonicalBinary(ReadOnlyMemory<byte> bytes)
    {
        if (bytes.Length != CanonicalByteLength)
        {
            throw new KeyFormatException($"Canonical signing public key must be exactly {CanonicalByteLength} bytes.");
        }

        var span = bytes.Span;
        var version = span[0];
        if (version != Version)
        {
            throw new KeyFormatException($"Unsupported signing public key version byte: expected 0x{Version:X2}, found 0x{version:X2}.");
        }

        var ed25519 = span.Slice(1, Ed25519Length).ToArray();
        var mldsa = span.Slice(1 + Ed25519Length, MlDsa87Length).ToArray();
        return new PqfSigningPublicKey(version, ed25519, mldsa);
    }

    public byte[] ToCanonicalBinary()
    {
        var output = new byte[CanonicalByteLength];
        output[0] = VersionByte;
        _ed25519PublicKey.CopyTo(output.AsSpan(1, Ed25519Length));
        _mlDsa87PublicKey.CopyTo(output.AsSpan(1 + Ed25519Length, MlDsa87Length));
        return output;
    }
}