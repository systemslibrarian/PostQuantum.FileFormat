using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace PostQuantum.FileFormat.Crypto;

public static class SecureZero
{
    public static void Clear(byte[]? bytes)
    {
        if (bytes is null)
        {
            return;
        }

        CryptographicOperations.ZeroMemory(bytes.AsSpan());
    }

    public static void Clear(Span<byte> bytes)
    {
        CryptographicOperations.ZeroMemory(bytes);
    }

    public static void Clear<T>(T[]? array) where T : struct
    {
        if (array is null)
        {
            return;
        }

        var span = MemoryMarshal.AsBytes(array.AsSpan());
        CryptographicOperations.ZeroMemory(span);
    }
}
