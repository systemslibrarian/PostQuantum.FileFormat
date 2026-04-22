namespace PostQuantum.FileFormat.Keys;

public sealed class PqfPublicKey
{
    public const int CanonicalByteLength = 1601;
    public const byte Version = 0x01;

    private const int X25519Length = 32;
    private const int MlKem1024Length = 1568;

    private readonly byte[] _x25519PublicKey;
    private readonly byte[] _mlKem1024PublicKey;

    private PqfPublicKey(byte versionByte, byte[] x25519PublicKey, byte[] mlKem1024PublicKey)
    {
        VersionByte = versionByte;
        _x25519PublicKey = x25519PublicKey;
        _mlKem1024PublicKey = mlKem1024PublicKey;
    }

    public byte VersionByte { get; }

    public ReadOnlyMemory<byte> X25519PublicKey => _x25519PublicKey.AsMemory();

    public ReadOnlyMemory<byte> MlKem1024PublicKey => _mlKem1024PublicKey.AsMemory();

    public static PqfPublicKey FromCanonicalBinary(ReadOnlyMemory<byte> bytes)
    {
        if (bytes.Length != CanonicalByteLength)
        {
            throw new KeyFormatException($"Canonical encryption public key must be exactly {CanonicalByteLength} bytes.");
        }

        var span = bytes.Span;
        var version = span[0];
        if (version != Version)
        {
            throw new KeyFormatException($"Unsupported encryption public key version byte: expected 0x{Version:X2}, found 0x{version:X2}.");
        }

        var x25519 = span.Slice(1, X25519Length).ToArray();
        var mlkem = span.Slice(1 + X25519Length, MlKem1024Length).ToArray();
        return new PqfPublicKey(version, x25519, mlkem);
    }

    public byte[] ToCanonicalBinary()
    {
        var output = new byte[CanonicalByteLength];
        output[0] = VersionByte;
        _x25519PublicKey.CopyTo(output.AsSpan(1, X25519Length));
        _mlKem1024PublicKey.CopyTo(output.AsSpan(1 + X25519Length, MlKem1024Length));
        return output;
    }
}