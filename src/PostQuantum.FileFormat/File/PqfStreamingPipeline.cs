using System.Buffers.Binary;
using System.Security.Cryptography;
using PostQuantum.FileFormat.Cbor;
using PostQuantum.FileFormat.Crypto;

namespace PostQuantum.FileFormat.File;

/// <summary>
/// True streaming PQF v1 reader: reads from a <see cref="Stream"/> without
/// materializing the entire file in memory. Header is bounded-buffered
/// (spec §3 caps it at 1 MiB), then chunks are surfaced one at a time, then
/// the footer and optional file signature are read and exposed.
///
/// This pipeline replaces the <c>byte[]</c>-bound walk inside
/// <see cref="PqfFileReader.OpenForValidation"/> for production decryption.
/// The legacy in-memory reader is preserved for tests and for callers that
/// already have the file in memory.
///
/// Callers MUST consume the pipeline in order:
///   1. Construct via <see cref="OpenAsync"/>; the header is parsed and
///      structurally validated immediately.
///   2. Iterate <see cref="EnumerateChunksAsync"/> to completion.
///   3. Call <see cref="ReadTrailerAsync"/> to read the footer and (when
///      signed) the file signature.
///
/// Skipping or re-ordering steps is a usage error and throws.
/// </summary>
internal sealed class PqfStreamingPipeline : IAsyncDisposable
{
    private const ushort PqfVersion = 0x0001;
    private const uint MaxHeaderLength = 1_048_576;
    private const int HybridSignatureLength = 4691;
    private const int FooterLength = 20;
    private const int ChunkFrameHeaderLength = 5;
    /// <summary>Largest legal chunk_size from the spec (16 MiB) plus the AEAD tag.</summary>
    private const int MaxChunkCiphertextLength = (16 * 1024 * 1024) + 16;

    private readonly Stream _source;
    private readonly bool _leaveOpen;
    private bool _chunksEnumerated;
    private bool _trailerRead;
    private bool _disposed;

    private PqfStreamingPipeline(Stream source, bool leaveOpen)
    {
        _source = source;
        _leaveOpen = leaveOpen;
    }

    private byte[]? _consumedFooterMagic;

    public PqfFileHeader Header { get; private set; } = null!;
    public ReadOnlyMemory<byte> HeaderBytes { get; private set; }
    public ReadOnlyMemory<byte> HeaderSignatureBytes { get; private set; }
    public ReadOnlyMemory<byte> FooterBytes { get; private set; }
    public ReadOnlyMemory<byte> FileSignatureBytes { get; private set; }
    public ulong ReportedChunkCount { get; private set; }
    public ulong ReportedPlaintextBytes { get; private set; }

    /// <summary>
    /// Open and validate a PQF file from a stream. Reads the magic, version,
    /// header length, header CBOR, and (when signed) the header signature.
    /// Performs structural and schema validation but does not verify the
    /// header signature — that is the caller's responsibility, because the
    /// caller owns the <see cref="Crypto.HybridSigner"/> instance.
    /// </summary>
    public static async Task<PqfStreamingPipeline> OpenAsync(
        Stream source,
        bool leaveOpen = true,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(source);

        var pipeline = new PqfStreamingPipeline(source, leaveOpen);
        await pipeline.ReadHeaderAsync(cancellationToken).ConfigureAwait(false);
        return pipeline;
    }

    private async Task ReadHeaderAsync(CancellationToken ct)
    {
        // 10-byte file prefix: magic(4) || version(2) || header_len(4)
        var prefix = new byte[10];
        await ReadExactlyAsync(prefix, "file prefix", ct).ConfigureAwait(false);

        if (!prefix.AsSpan(0, 4).SequenceEqual("PQF1"u8))
        {
            throw new PqfFileException(PqfRefusalReason.MagicMismatch, "File magic mismatch: expected 'PQF1'", offset: 0);
        }
        var version = BinaryPrimitives.ReadUInt16BigEndian(prefix.AsSpan(4, 2));
        if (version != PqfVersion)
        {
            throw new PqfFileException(PqfRefusalReason.VersionMismatch, $"Version mismatch: expected {PqfVersion:X4}, got {version:X4}", offset: 4);
        }
        var headerLength = BinaryPrimitives.ReadUInt32BigEndian(prefix.AsSpan(6, 4));
        if (headerLength == 0 || headerLength > MaxHeaderLength)
        {
            throw new PqfFileException(PqfRefusalReason.HeaderLengthExceedsLimit, $"Header length invalid: {headerLength}", offset: 6);
        }

        var headerBytes = new byte[headerLength];
        await ReadExactlyAsync(headerBytes, "header", ct).ConfigureAwait(false);
        HeaderBytes = headerBytes;

        CborValue headerValue;
        try
        {
            headerValue = DeterministicCborValidator.ParseStrict(headerBytes);
        }
        catch (CborValidationException ex)
        {
            var reason = ex.Message switch
            {
                var msg when msg.Contains("non-shortest") => PqfRefusalReason.NonDeterministicCborEncoding,
                var msg when msg.Contains("indefinite") => PqfRefusalReason.NonDeterministicCborEncoding,
                var msg when msg.Contains("Trailing bytes") => PqfRefusalReason.TrailingDataAfterExpectedEof,
                var msg when msg.Contains("duplicate") => PqfRefusalReason.DuplicateCborKey,
                var msg when msg.Contains("order") => PqfRefusalReason.NonDeterministicCborEncoding,
                _ => PqfRefusalReason.NonDeterministicCborEncoding,
            };
            throw new PqfFileException(reason, $"CBOR validation failed: {ex.Message}", offset: 10);
        }

        Header = HeaderCborReader.Parse(headerValue);

        if (Header.Signer is not null)
        {
            var sig = new byte[HybridSignatureLength];
            await ReadExactlyAsync(sig, "header signature", ct).ConfigureAwait(false);
            HeaderSignatureBytes = sig;
        }
    }

    /// <summary>
    /// Enumerate ciphertext chunks one at a time. Each yielded chunk is a
    /// freshly allocated buffer that the caller may zero after use. The
    /// per-chunk SHA-256 hasher is updated with the chunk's frame bytes
    /// (5-byte header + ciphertext) for later file-signature verification.
    /// </summary>
    public async IAsyncEnumerable<StreamedChunk> EnumerateChunksAsync(
        IncrementalHash chunkHasher,
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(chunkHasher);
        if (_chunksEnumerated)
        {
            throw new InvalidOperationException("Chunks have already been enumerated.");
        }
        _chunksEnumerated = true;

        var maxChunkCiphertext = checked(Header.ChunkSize + 16);
        if (maxChunkCiphertext > MaxChunkCiphertextLength)
        {
            // Header.ChunkSize is bounded by HeaderCborReader, but defense in depth.
            throw new PqfFileException(PqfRefusalReason.ChunkSizeInvalid, "chunk_size exceeds streaming bound");
        }

        ulong index = 0;
        var frameHeader = new byte[ChunkFrameHeaderLength];
        ulong observedPlaintext = 0;
        var sawFinal = false;

        while (!sawFinal)
        {
            // Each chunk frame is 5 bytes: 4-byte big-endian length, 1 flag byte.
            // We first peek the 4-byte length. The footer magic 'PQFE' encodes
            // as 0x50514645 = 1347503685, vastly larger than the per-chunk
            // bound chunk_size+16 (≤ 16 MiB + 16). A chunk's length field can
            // therefore NEVER coincidentally collide with the footer magic, so
            // we use that magic as the sentinel that distinguishes "next chunk"
            // from "footer reached".
            var lenBuf = new byte[4];
            var n = await ReadExactlyOrEofAsync(lenBuf, ct).ConfigureAwait(false);
            if (n == 0)
            {
                throw new PqfFileException(PqfRefusalReason.TruncationDetected, "Stream ended without final-chunk flag");
            }
            if (n < 4)
            {
                throw new PqfFileException(PqfRefusalReason.TruncationDetected, "Chunk frame header truncated");
            }

            if (lenBuf.AsSpan().SequenceEqual("PQFE"u8))
            {
                // Footer reached. Permitted only when no prior chunk was
                // declared the final chunk and the in-flight chunk index is
                // zero (true streaming-empty file). If any chunks have been
                // emitted, hitting the footer prior to a final-flag chunk is
                // a truncation.
                if (index > 0)
                {
                    throw new PqfFileException(PqfRefusalReason.TruncationDetected, "Footer reached before final-chunk flag");
                }
                _consumedFooterMagic = lenBuf;
                break;
            }

            var flagBuf = new byte[1];
            await ReadExactlyAsync(flagBuf, "chunk flag byte", ct).ConfigureAwait(false);
            frameHeader[0] = lenBuf[0];
            frameHeader[1] = lenBuf[1];
            frameHeader[2] = lenBuf[2];
            frameHeader[3] = lenBuf[3];
            frameHeader[4] = flagBuf[0];

            var chunkLen = BinaryPrimitives.ReadUInt32BigEndian(frameHeader.AsSpan(0, 4));
            var flags = frameHeader[4];
            if ((flags & 0xfe) != 0)
            {
                throw new PqfFileException(PqfRefusalReason.ReservedChunkFlagBitsSet, $"Reserved chunk flag bits set: 0x{flags:X2}");
            }
            var isFinal = (flags & 0x01) != 0;
            if (chunkLen < 16)
            {
                throw new PqfFileException(PqfRefusalReason.ChunkLengthExceedsRemainingBytes, "Chunk length below AEAD tag size");
            }
            if (chunkLen > (uint)maxChunkCiphertext)
            {
                throw new PqfFileException(PqfRefusalReason.ChunkLengthExceedsRemainingBytes, $"Chunk length {chunkLen} exceeds chunk_size+16 ({maxChunkCiphertext})");
            }

            var ciphertext = new byte[chunkLen];
            await ReadExactlyAsync(ciphertext, $"chunk {index}", ct).ConfigureAwait(false);

            chunkHasher.AppendData(frameHeader);
            chunkHasher.AppendData(ciphertext);

            observedPlaintext += chunkLen - 16;
            sawFinal = isFinal;
            yield return new StreamedChunk(index, isFinal, ciphertext);
            index++;
        }

        // Stash counts so the trailer step can validate against them.
        ReportedChunkCount = index;
        ReportedPlaintextBytes = observedPlaintext;
    }

    /// <summary>
    /// Read and validate the 20-byte footer, then (when signed) read the
    /// 4691-byte file signature and validate that no trailing bytes follow.
    /// </summary>
    public async Task ReadTrailerAsync(CancellationToken ct = default)
    {
        if (!_chunksEnumerated)
        {
            throw new InvalidOperationException("Trailer cannot be read before chunks are enumerated.");
        }
        if (_trailerRead)
        {
            throw new InvalidOperationException("Trailer already read.");
        }
        _trailerRead = true;

        var footer = new byte[FooterLength];
        if (_consumedFooterMagic is not null)
        {
            // The chunk loop already consumed the 4-byte footer magic to
            // distinguish "next chunk" from "end of chunks". Splice it back in.
            _consumedFooterMagic.CopyTo(footer, 0);
            await ReadExactlyAsync(new ArraySegment<byte>(footer, 4, FooterLength - 4), "footer (post-magic)", ct).ConfigureAwait(false);
        }
        else
        {
            await ReadExactlyAsync(footer, "footer", ct).ConfigureAwait(false);
        }
        FooterBytes = footer;

        if (!footer.AsSpan(0, 4).SequenceEqual("PQFE"u8))
        {
            throw new PqfFileException(PqfRefusalReason.FooterMagicInvalid, "Footer magic mismatch: expected 'PQFE'");
        }

        var footerChunkCount = BinaryPrimitives.ReadUInt64BigEndian(footer.AsSpan(4, 8));
        var footerPlaintextBytes = BinaryPrimitives.ReadUInt64BigEndian(footer.AsSpan(12, 8));

        if (footerChunkCount != ReportedChunkCount)
        {
            throw new PqfFileException(
                PqfRefusalReason.FooterChunkCountMismatch,
                $"Footer chunk_count {footerChunkCount} != observed {ReportedChunkCount}");
        }
        if (footerPlaintextBytes != ReportedPlaintextBytes)
        {
            throw new PqfFileException(
                PqfRefusalReason.FooterPlaintextBytesMismatch,
                $"Footer plaintext_bytes {footerPlaintextBytes} != observed {ReportedPlaintextBytes}");
        }

        if (Header.Signer is not null)
        {
            var fileSig = new byte[HybridSignatureLength];
            await ReadExactlyAsync(fileSig, "file signature", ct).ConfigureAwait(false);
            FileSignatureBytes = fileSig;
        }

        // Confirm the stream is at EOF; any extra byte is trailing data.
        var probe = new byte[1];
        var extra = await _source.ReadAsync(probe.AsMemory(0, 1), ct).ConfigureAwait(false);
        if (extra != 0)
        {
            throw new PqfFileException(PqfRefusalReason.TrailingDataAfterExpectedEof, "Trailing data after expected EOF");
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        if (!_leaveOpen)
        {
            await _source.DisposeAsync().ConfigureAwait(false);
        }
    }

    private async Task ReadExactlyAsync(byte[] destination, string sectionLabel, CancellationToken ct)
    {
        var read = await _source.ReadAtLeastAsync(destination, destination.Length, throwOnEndOfStream: false, ct).ConfigureAwait(false);
        if (read != destination.Length)
        {
            throw new PqfFileException(PqfRefusalReason.TruncationDetected, $"Stream truncated while reading {sectionLabel}: needed {destination.Length} bytes, got {read}");
        }
    }

    private async Task ReadExactlyAsync(ArraySegment<byte> destination, string sectionLabel, CancellationToken ct)
    {
        var read = await _source.ReadAtLeastAsync(destination, destination.Count, throwOnEndOfStream: false, ct).ConfigureAwait(false);
        if (read != destination.Count)
        {
            throw new PqfFileException(PqfRefusalReason.TruncationDetected, $"Stream truncated while reading {sectionLabel}: needed {destination.Count} bytes, got {read}");
        }
    }

    private async Task<int> ReadExactlyOrEofAsync(byte[] destination, CancellationToken ct)
    {
        var read = await _source.ReadAtLeastAsync(destination, destination.Length, throwOnEndOfStream: false, ct).ConfigureAwait(false);
        return read;
    }
}

/// <summary>
/// One ciphertext chunk surfaced by <see cref="PqfStreamingPipeline.EnumerateChunksAsync"/>.
/// The <see cref="Ciphertext"/> array is owned by the consumer; consumers
/// SHOULD <see cref="SecureZero.Clear(byte[]?)"/> it after use.
/// </summary>
internal readonly record struct StreamedChunk(ulong Index, bool IsFinal, byte[] Ciphertext);
