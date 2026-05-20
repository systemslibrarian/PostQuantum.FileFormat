using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Jobs;
using PostQuantum.FileFormat.Crypto;
using PostQuantum.FileFormat.File;
using PostQuantum.FileFormat.Keys;

namespace PostQuantum.FileFormat.Bench;

[MemoryDiagnoser]
[SimpleJob(RuntimeMoniker.Net80, warmupCount: 2, iterationCount: 5)]
public class HeaderParseBenchmarks
{
    private byte[] _container = null!;

    [GlobalSetup]
    public void Setup()
    {
        var provider = CryptoProvider.Detect();
        using var identity = PqfIdentity.Generate(provider);
        var plaintext = new byte[4096];
        System.Security.Cryptography.RandomNumberGenerator.Fill(plaintext);

        using var enc = new MemoryStream();
        using var src = new MemoryStream(plaintext);
        PqfFile.EncryptAsync(src, enc, new[] { identity.PublicKey }, signer: null).GetAwaiter().GetResult();
        _container = enc.ToArray();
    }

    /// <summary>
    /// Header parse + structural validation. This is the cost paid by
    /// every reader before any plaintext is touched — including
    /// `pqf inspect`, which never decrypts.
    /// </summary>
    [Benchmark]
    public async Task<int> Parse_header_only()
    {
        using var ms = new MemoryStream(_container, writable: false);
        await using var pipeline = await PqfStreamingPipeline.OpenAsync(ms, leaveOpen: true);
        return pipeline.Header.Recipients.Count;
    }
}
