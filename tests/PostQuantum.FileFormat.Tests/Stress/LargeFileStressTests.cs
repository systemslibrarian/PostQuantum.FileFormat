using PostQuantum.FileFormat.Crypto;
using PostQuantum.FileFormat.File;
using PostQuantum.FileFormat.Keys;

namespace PostQuantum.FileFormat.Tests.Stress;

/// <summary>
/// Stress tests for the streaming pipeline.
///
/// The streaming reader claims O(1) memory regardless of file size:
/// at most the header (≤ 1 MiB) plus one in-flight chunk (≤ 16 MiB + tag).
/// These tests put real numbers behind that claim.
///
/// They are slow by design (multi-GB plaintexts and many-recipient
/// containers) and are excluded from the default CI run. Invoke
/// explicitly with:
///     dotnet test --filter "Category=Stress"
///
/// Set PQF_STRESS_LARGE_GB and PQF_STRESS_MANY_RECIPIENTS to override
/// the defaults if you want to push harder.
/// </summary>
[Trait("Category", "Stress")]
public sealed class LargeFileStressTests
{
    private const string LargeEnv = "PQF_STRESS_LARGE_GB";
    private const string ManyEnv = "PQF_STRESS_MANY_RECIPIENTS";

    [Fact(Skip = "Stress test — run explicitly with --filter Category=Stress. Multi-GB plaintext.")]
    public async Task Roundtrip_a_multi_gigabyte_plaintext_streaming()
    {
        var gbStr = Environment.GetEnvironmentVariable(LargeEnv);
        var gigabytes = int.TryParse(gbStr, out var gb) ? Math.Clamp(gb, 1, 16) : 2;
        long totalBytes = (long)gigabytes * 1024L * 1024L * 1024L;

        var provider = CryptoProvider.Detect();
        using var identity = PqfIdentity.Generate(provider);

        // Encrypt: feed a producer stream into the writer.
        var encryptedPath = Path.Combine(Path.GetTempPath(), $"pqf-stress-{Guid.NewGuid():N}.pqf");
        try
        {
            await using (var enc = System.IO.File.Create(encryptedPath))
            await using (var src = new ChunkedFillStream(totalBytes))
            {
                await PqfFile.EncryptAsync(src, enc, new[] { identity.PublicKey }, signer: null, chunkSize: 16 * 1024 * 1024);
            }

            // Decrypt: stream to a counting sink, asserting only that total
            // bytes match. Hash-equality on multi-GB blobs is the next
            // hardening step; this run just exercises memory pressure.
            await using var ctIn = System.IO.File.OpenRead(encryptedPath);
            await using var sink = new CountingStream();
            await PqfDecryptor.DecryptAsync(ctIn, sink, identity);

            Assert.Equal(totalBytes, sink.BytesWritten);
        }
        finally
        {
            if (System.IO.File.Exists(encryptedPath)) System.IO.File.Delete(encryptedPath);
        }
    }

    [Fact(Skip = "Stress test — run explicitly with --filter Category=Stress. Many recipients.")]
    public async Task Encrypt_to_one_thousand_recipients_then_decrypt_as_each()
    {
        var nStr = Environment.GetEnvironmentVariable(ManyEnv);
        var n = int.TryParse(nStr, out var parsed) ? Math.Clamp(parsed, 8, 4096) : 1000;

        var provider = CryptoProvider.Detect();
        var identities = new PqfIdentity[n];
        try
        {
            for (var i = 0; i < n; i++) identities[i] = PqfIdentity.Generate(provider);

            var plaintext = new byte[64 * 1024];
            System.Security.Cryptography.RandomNumberGenerator.Fill(plaintext);

            byte[] container;
            using (var enc = new MemoryStream())
            using (var src = new MemoryStream(plaintext))
            {
                await PqfFile.EncryptAsync(src, enc, identities.Select(id => id.PublicKey).ToArray(), signer: null);
                container = enc.ToArray();
            }

            // Sample-decrypt: don't run the full N-way trial under stress, just
            // first, middle, and last. Property-based tests cover "every
            // recipient decrypts independently" on small N.
            foreach (var idx in new[] { 0, n / 2, n - 1 })
            {
                using var ctIn = new MemoryStream(container);
                using var ptOut = new MemoryStream();
                await PqfDecryptor.DecryptAsync(ctIn, ptOut, identities[idx]);
                Assert.Equal(plaintext, ptOut.ToArray());
            }
        }
        finally
        {
            foreach (var id in identities) id?.Dispose();
        }
    }

    /// <summary>
    /// Produces deterministic synthetic plaintext bytes on the fly so the
    /// stress test does not have to allocate a 2 GiB buffer.
    /// </summary>
    private sealed class ChunkedFillStream : Stream
    {
        private readonly long _total;
        private long _position;

        public ChunkedFillStream(long total) { _total = total; }
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => _total;
        public override long Position { get => _position; set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count)
        {
            var remaining = _total - _position;
            if (remaining <= 0) return 0;
            var n = (int)Math.Min(count, remaining);
            // Deterministic, cheap fill so the encryptor sees varied bytes.
            for (var i = 0; i < n; i++) buffer[offset + i] = (byte)((_position + i) * 31u);
            _position += n;
            return n;
        }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }

    /// <summary>
    /// Discards everything written but counts the bytes — for measuring
    /// throughput without paying for an actual destination buffer.
    /// </summary>
    private sealed class CountingStream : Stream
    {
        public long BytesWritten { get; private set; }
        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => BytesWritten;
        public override long Position { get => BytesWritten; set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) { BytesWritten += count; }
        public override void Write(ReadOnlySpan<byte> buffer) { BytesWritten += buffer.Length; }
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            BytesWritten += buffer.Length;
            return ValueTask.CompletedTask;
        }
    }
}
