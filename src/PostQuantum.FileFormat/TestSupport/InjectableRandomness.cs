using System.Buffers.Binary;
using System.Security.Cryptography;

namespace PostQuantum.FileFormat.TestSupport;

internal sealed class InjectableRandomness
{
    private readonly byte[] _seed;
    private ulong _counter;

    public InjectableRandomness(ReadOnlyMemory<byte> seed)
    {
        if (seed.Length == 0)
        {
            throw new ArgumentException("Seed must not be empty", nameof(seed));
        }

        _seed = seed.ToArray();
        _counter = 0;
    }

    public void Fill(Span<byte> destination)
    {
        var offset = 0;
        Span<byte> counterBytes = stackalloc byte[8];

        while (offset < destination.Length)
        {
            BinaryPrimitives.WriteUInt64BigEndian(counterBytes, _counter++);
            var blockInput = new byte[_seed.Length + 8];
            _seed.CopyTo(blockInput, 0);
            counterBytes.CopyTo(blockInput.AsSpan(_seed.Length));
            var digest = SHA256.HashData(blockInput);

            var toCopy = Math.Min(digest.Length, destination.Length - offset);
            digest.AsSpan(0, toCopy).CopyTo(destination[offset..]);
            offset += toCopy;

            CryptographicOperations.ZeroMemory(blockInput);
            CryptographicOperations.ZeroMemory(digest);
        }
    }
}
