using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace PostQuantum.FileFormat.Crypto;

/// <summary>
/// Thin, null-and-span-safe wrapper over
/// <see cref="System.Security.Cryptography.CryptographicOperations.ZeroMemory(Span{byte})"/>.
/// Every overload below terminates in that BCL call, which performs a real,
/// non-elidable zero on all supported .NET runtimes: it is implemented in
/// unmanaged code that the JIT does not see, so dead-store elimination cannot
/// remove the write. This wrapper exists only to (a) accept a nullable
/// <c>byte[]?</c> without a null-check at every call site, and (b) zero an
/// arbitrary <c>T[]</c> where <c>T : struct</c> via
/// <see cref="System.Runtime.InteropServices.MemoryMarshal.AsBytes{T}"/>.
/// All secret-zeroing in this assembly funnels through here so the guarantee
/// can be audited in one file.
/// </summary>
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
