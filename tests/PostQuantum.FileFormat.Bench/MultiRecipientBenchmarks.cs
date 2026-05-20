using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Jobs;
using PostQuantum.FileFormat.Crypto;
using PostQuantum.FileFormat.File;
using PostQuantum.FileFormat.Keys;

namespace PostQuantum.FileFormat.Bench;

[MemoryDiagnoser]
[SimpleJob(RuntimeMoniker.Net80, warmupCount: 2, iterationCount: 5)]
public class MultiRecipientBenchmarks
{
    [Params(1, 4, 16, 64)]
    public int RecipientCount { get; set; }

    private PqfIdentity[] _identities = null!;
    private byte[] _encrypted = null!;
    private byte[] _plaintext = null!;

    [GlobalSetup]
    public void Setup()
    {
        var provider = CryptoProvider.Detect();
        _identities = new PqfIdentity[RecipientCount];
        for (var i = 0; i < RecipientCount; i++)
        {
            _identities[i] = PqfIdentity.Generate(provider);
        }

        _plaintext = new byte[64 * 1024];
        System.Security.Cryptography.RandomNumberGenerator.Fill(_plaintext);

        using var enc = new MemoryStream();
        using var src = new MemoryStream(_plaintext);
        PqfFile.EncryptAsync(src, enc, _identities.Select(i => i.PublicKey).ToArray(), signer: null)
            .GetAwaiter().GetResult();
        _encrypted = enc.ToArray();
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        if (_identities is null) return;
        foreach (var id in _identities) id?.Dispose();
    }

    /// <summary>
    /// Encrypt to N recipients. Expected to scale ~linearly in N
    /// because the writer runs one X25519/ML-KEM pair per recipient.
    /// </summary>
    [Benchmark]
    public byte[] Encrypt_to_N_recipients()
    {
        using var enc = new MemoryStream();
        using var src = new MemoryStream(_plaintext);
        PqfFile.EncryptAsync(src, enc, _identities.Select(i => i.PublicKey).ToArray(), signer: null)
            .GetAwaiter().GetResult();
        return enc.ToArray();
    }

    /// <summary>
    /// Decrypt as the FIRST recipient. Combined with Decrypt_as_last_recipient
    /// this measures the constant-time-recipient-trial cost we care about:
    /// the difference between these two numbers should be small and noise-
    /// dominated.
    /// </summary>
    [Benchmark]
    public byte[] Decrypt_as_first_recipient()
    {
        using var dec = new MemoryStream(_plaintext.Length);
        using var src = new MemoryStream(_encrypted);
        PqfDecryptor.DecryptAsync(src, dec, _identities[0]).GetAwaiter().GetResult();
        return dec.ToArray();
    }

    [Benchmark]
    public byte[] Decrypt_as_last_recipient()
    {
        using var dec = new MemoryStream(_plaintext.Length);
        using var src = new MemoryStream(_encrypted);
        PqfDecryptor.DecryptAsync(src, dec, _identities[^1]).GetAwaiter().GetResult();
        return dec.ToArray();
    }
}
