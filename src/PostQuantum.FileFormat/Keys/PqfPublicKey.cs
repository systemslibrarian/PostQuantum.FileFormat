namespace PostQuantum.FileFormat.Keys;

public sealed class PqfPublicKey
{
    public const int CanonicalByteLength = 1217;
    public const byte Version = 0x01;

    private const int X25519Length = 32;
    private const int MlKem768Length = 1184;

    private readonly byte[] _x25519PublicKey;
    private readonly byte[] _mlKem768PublicKey;

    private PqfPublicKey(byte versionByte, byte[] x25519PublicKey, byte[] mlKem768PublicKey)
    {
        VersionByte = versionByte;
        _x25519PublicKey = x25519PublicKey;
        _mlKem768PublicKey = mlKem768PublicKey;
    }

    public byte VersionByte { get; }

    public ReadOnlyMemory<byte> X25519PublicKey => _x25519PublicKey.AsMemory();

    public ReadOnlyMemory<byte> MlKem768PublicKey => _mlKem768PublicKey.AsMemory();

    public static PqfPublicKey FromParts(ReadOnlySpan<byte> x25519PublicKey, ReadOnlySpan<byte> mlKem768PublicKey)
    {
        if (x25519PublicKey.Length != X25519Length)
        {
            throw new KeyFormatException($"X25519 public key must be exactly {X25519Length} bytes.");
        }

        if (mlKem768PublicKey.Length != MlKem768Length)
        {
            throw new KeyFormatException($"ML-KEM-768 public key must be exactly {MlKem768Length} bytes.");
        }

        return new PqfPublicKey(Version, x25519PublicKey.ToArray(), mlKem768PublicKey.ToArray());
    }

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
        var mlkem = span.Slice(1 + X25519Length, MlKem768Length).ToArray();
        return new PqfPublicKey(version, x25519, mlkem);
    }

    public byte[] ToCanonicalBinary()
    {
        var output = new byte[CanonicalByteLength];
        output[0] = VersionByte;
        _x25519PublicKey.CopyTo(output.AsSpan(1, X25519Length));
        _mlKem768PublicKey.CopyTo(output.AsSpan(1 + X25519Length, MlKem768Length));
        return output;
    }
}
