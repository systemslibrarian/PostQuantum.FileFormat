using PostQuantum.FileFormat.File;
using PostQuantum.FileFormat.Keys;
using System.Reflection;

namespace PostQuantum.FileFormat.Tests.File;

public sealed class PqfFileWriterTests
{
    [Fact]
    public async Task EncryptAsync_empty_plaintext_produces_parsable_file()
    {
        using var identity = PqfIdentity.Generate();
        using var source = new MemoryStream(Array.Empty<byte>());
        using var destination = new MemoryStream();

        await PqfFileWriter.EncryptAsync(source, destination, new[] { identity.PublicKey }, signer: null);

        var bytes = destination.ToArray();
        var reader = PqfFileReader.OpenForValidation(bytes);
        Assert.NotNull(reader);
        Assert.Equal(0UL, reader.TotalChunkCount);
        Assert.Equal(0UL, reader.ReportedPlaintextBytes);
    }

    [Fact]
    public async Task EncryptAsync_signed_file_includes_signatures()
    {
        using var identity = PqfIdentity.Generate();
        using var signer = PqfSigningIdentity.Generate();
        using var source = new MemoryStream(new byte[5000]);
        using var destination = new MemoryStream();

        await PqfFileWriter.EncryptAsync(source, destination, new[] { identity.PublicKey }, signer);

        var reader = PqfFileReader.OpenForValidation(destination.ToArray());
        Assert.Equal(4691, reader.HeaderSignatureBytes.Length);
        Assert.Equal(4691, reader.FileSignatureBytes.Length);
    }

    [Fact]
    public async Task EncryptAsync_100_recipients_produces_parsable_file()
    {
        var identities = new List<PqfIdentity>();
        try
        {
            for (var i = 0; i < 100; i++)
            {
                identities.Add(PqfIdentity.Generate());
            }

            using var source = new MemoryStream(new byte[1234]);
            using var destination = new MemoryStream();
            await PqfFileWriter.EncryptAsync(source, destination, identities.Select(i => i.PublicKey).ToArray(), signer: null);

            var reader = PqfFileReader.OpenForValidation(destination.ToArray());
            Assert.Equal(100, reader.Header.Recipients.Count);
        }
        finally
        {
            foreach (var id in identities)
            {
                id.Dispose();
            }
        }
    }

    [Fact]
    public async Task EncryptAsync_short_read_source_still_emits_full_non_final_chunks()
    {
        using var identity = PqfIdentity.Generate();
        var plaintext = new byte[(4096 * 2) + 123];
        Random.Shared.NextBytes(plaintext);

        using var source = new OneByteReadStream(plaintext);
        using var destination = new MemoryStream();

        await PqfFileWriter.EncryptAsync(source, destination, new[] { identity.PublicKey }, signer: null, chunkSize: 4096);

        var reader = PqfFileReader.OpenForValidation(destination.ToArray());
        Assert.Equal(3, reader.Chunks.Count);
        Assert.Equal(4096, reader.Chunks[0].PlaintextLength);
        Assert.Equal(4096, reader.Chunks[1].PlaintextLength);
        Assert.Equal(123, reader.Chunks[2].PlaintextLength);
        Assert.False(reader.Chunks[0].IsFinal);
        Assert.False(reader.Chunks[1].IsFinal);
        Assert.True(reader.Chunks[2].IsFinal);
    }

    [Fact]
    public void Deterministic_test_hooks_are_not_public_api_surface()
    {
        var encryptOverloads = typeof(PqfFileWriter)
            .GetMethods(BindingFlags.Public | BindingFlags.Static)
            .Where(m => m.Name == nameof(PqfFileWriter.EncryptAsync))
            .ToArray();

        Assert.Single(encryptOverloads);
        Assert.DoesNotContain(encryptOverloads[0].GetParameters(), p => p.ParameterType.Name.Contains("InjectableRandomness", StringComparison.Ordinal));
        Assert.DoesNotContain(encryptOverloads[0].GetParameters(), p => string.Equals(p.Name, "deterministicSigning", StringComparison.Ordinal));

        Assert.DoesNotContain(
            typeof(PostQuantum.FileFormat.Crypto.HybridSigner).GetMethods(BindingFlags.Public | BindingFlags.Instance),
            m => string.Equals(m.Name, "SignDeterministic", StringComparison.Ordinal));
    }

    private sealed class OneByteReadStream : MemoryStream
    {
        public OneByteReadStream(byte[] buffer)
            : base(buffer, writable: false)
        {
        }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            var slice = buffer.Length == 0 ? buffer : buffer[..1];
            return base.ReadAsync(slice, cancellationToken);
        }
    }
}
