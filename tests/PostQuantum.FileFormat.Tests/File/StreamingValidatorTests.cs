using System.Buffers.Binary;
using System.Security.Cryptography;
using PostQuantum.FileFormat.File;
using PostQuantum.FileFormat.Keys;

namespace PostQuantum.FileFormat.Tests.File;

/// <summary>
/// Tests pinning the Phase B streaming-validator contract: the decryption
/// pipeline must work over a forward-only, length-unknown <see cref="Stream"/>
/// without buffering the entire ciphertext, and must refuse cleanly when
/// the stream is truncated mid-payload.
/// </summary>
public sealed class StreamingValidatorTests
{
    [Fact]
    public async Task Decrypts_from_non_seekable_unknown_length_stream()
    {
        using var identity = PqfIdentity.Generate();
        var plaintext = RandomBytes(2_500_000); // > 2 MiB, multiple chunks

        using var encryptedBuffer = new MemoryStream();
        await PqfFileWriter.EncryptAsync(new MemoryStream(plaintext), encryptedBuffer, new[] { identity.PublicKey }, signer: null);

        // Wrap the ciphertext in a stream that refuses Length / Seek and that
        // hands out bytes only in small bursts, so any path that secretly
        // tries to materialize the whole thing or seek backward will fail.
        var ciphertext = encryptedBuffer.ToArray();
        await using var nonSeekable = new ForwardOnlyStream(ciphertext, maxBurst: 73);

        using var decrypted = new MemoryStream();
        await PqfFileReader.DecryptAsync(nonSeekable, decrypted, identity);

        Assert.Equal(plaintext, decrypted.ToArray());
    }

    [Fact]
    public async Task Truncated_payload_refuses_in_authenticated_mode_without_releasing_plaintext()
    {
        using var identity = PqfIdentity.Generate();
        var plaintext = RandomBytes(50_000);

        using var encryptedBuffer = new MemoryStream();
        await PqfFileWriter.EncryptAsync(new MemoryStream(plaintext), encryptedBuffer, new[] { identity.PublicKey }, signer: null);

        // Lop off the trailing 25 bytes — well into the footer / past it for
        // unsigned files. Authenticated mode must refuse and emit nothing.
        var truncated = encryptedBuffer.ToArray()[..^25];
        await using var nonSeekable = new ForwardOnlyStream(truncated, maxBurst: 4096);

        using var output = new MemoryStream();
        var ex = await Assert.ThrowsAsync<PqfFileException>(() => PqfFileReader.DecryptAsync(nonSeekable, output, identity));
        Assert.Equal(PqfRefusalReason.TruncationDetected, ex.Reason);
        Assert.Equal(0, output.Length);
    }

    [Fact]
    public async Task Forged_chunk_length_uint_max_refused_at_per_chunk_bound()
    {
        using var identity = PqfIdentity.Generate();
        var plaintext = RandomBytes(50_000);

        using var encryptedBuffer = new MemoryStream();
        await PqfFileWriter.EncryptAsync(new MemoryStream(plaintext), encryptedBuffer, new[] { identity.PublicKey }, signer: null);

        // Locate the first chunk frame (immediately after the 10-byte prefix
        // and the header CBOR; no header signature on unsigned files).
        var bytes = encryptedBuffer.ToArray();
        var headerLen = BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(6, 4));
        var firstChunkLengthOffset = 10 + (int)headerLen;
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(firstChunkLengthOffset, 4), uint.MaxValue);

        await using var src = new ForwardOnlyStream(bytes, maxBurst: 4096);
        using var output = new MemoryStream();
        var ex = await Assert.ThrowsAsync<PqfFileException>(() => PqfFileReader.DecryptAsync(src, output, identity));
        Assert.Equal(PqfRefusalReason.ChunkLengthExceedsRemainingBytes, ex.Reason);
        Assert.Equal(0, output.Length);
    }

    private static byte[] RandomBytes(int n)
    {
        var b = new byte[n];
        RandomNumberGenerator.Fill(b);
        return b;
    }

    /// <summary>
    /// Read-only stream that refuses <see cref="Stream.Length"/> /
    /// <see cref="Stream.Seek"/> / <see cref="Stream.Position"/> and that
    /// hands out at most <c>maxBurst</c> bytes per <see cref="Read"/>, so any
    /// pipeline that depends on knowing the file length up-front, seeking
    /// backwards, or assuming long bursts will fail loudly.
    /// </summary>
    private sealed class ForwardOnlyStream : Stream
    {
        private readonly byte[] _buf;
        private int _offset;
        private readonly int _maxBurst;

        public ForwardOnlyStream(byte[] buffer, int maxBurst)
        {
            _buf = buffer;
            _maxBurst = Math.Max(1, maxBurst);
        }

        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();

        public override int Read(byte[] buffer, int offset, int count)
        {
            var remaining = _buf.Length - _offset;
            if (remaining <= 0) return 0;
            var n = Math.Min(Math.Min(count, _maxBurst), remaining);
            Buffer.BlockCopy(_buf, _offset, buffer, offset, n);
            _offset += n;
            return n;
        }

        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            var remaining = _buf.Length - _offset;
            if (remaining <= 0) return ValueTask.FromResult(0);
            var n = Math.Min(Math.Min(buffer.Length, _maxBurst), remaining);
            _buf.AsSpan(_offset, n).CopyTo(buffer.Span);
            _offset += n;
            return ValueTask.FromResult(n);
        }
    }
}
