using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Jobs;
using PostQuantum.FileFormat.Crypto;
using PostQuantum.FileFormat.File;
using PostQuantum.FileFormat.Keys;

namespace PostQuantum.FileFormat.Bench;

[MemoryDiagnoser]
[SimpleJob(RuntimeMoniker.Net80, warmupCount: 2, iterationCount: 5)]
public class EncryptDecryptBenchmarks
{
    [Params(64 * 1024, 1024 * 1024, 16 * 1024 * 1024)]
    public int PlaintextBytes { get; set; }

    private byte[] _plaintext = null!;
    private PqfIdentity _identity = null!;
    private byte[] _encrypted = null!;

    [GlobalSetup]
    public void Setup()
    {
        var provider = CryptoProvider.Detect();
        _identity = PqfIdentity.Generate(provider);
        _plaintext = new byte[PlaintextBytes];
        System.Security.Cryptography.RandomNumberGenerator.Fill(_plaintext);

        using var enc = new MemoryStream();
        using var src = new MemoryStream(_plaintext);
        PqfFile.EncryptAsync(src, enc, new[] { _identity.PublicKey }, signer: null).GetAwaiter().GetResult();
        _encrypted = enc.ToArray();
    }

    [GlobalCleanup]
    public void Cleanup() => _identity?.Dispose();

    [Benchmark]
    public byte[] Encrypt_unsigned()
    {
        using var enc = new MemoryStream(_plaintext.Length + 64 * 1024);
        using var src = new MemoryStream(_plaintext);
        PqfFile.EncryptAsync(src, enc, new[] { _identity.PublicKey }, signer: null).GetAwaiter().GetResult();
        return enc.ToArray();
    }

    [Benchmark]
    public byte[] Decrypt_authenticated()
    {
        using var dec = new MemoryStream(_plaintext.Length);
        using var src = new MemoryStream(_encrypted);
        PqfDecryptor.DecryptAsync(src, dec, _identity).GetAwaiter().GetResult();
        return dec.ToArray();
    }
}
