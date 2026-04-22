using PostQuantum.FileFormat.File;
using PostQuantum.FileFormat.Keys;

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
        Assert.Equal(0, reader.TotalChunkCount);
        Assert.Equal(0, reader.ReportedPlaintextBytes);
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
}
