using System.Buffers.Binary;
using System.Security.Cryptography;
using PostQuantum.FileFormat.Cbor;
using PostQuantum.FileFormat.Crypto;
using PostQuantum.FileFormat.Keys;

namespace PostQuantum.FileFormat.File;

/// <summary>
/// PQF file parser with fail-closed validation and Phase 3 cryptographic decrypt support.
/// </summary>
public sealed class PqfFileReader
{
    private const ushort PqfVersion = 0x0001;
    private const uint MaxHeaderLength = 1_048_576; // 1 MiB per spec §3
    private const int HybridSignatureLength = 4691;

    internal sealed record ChunkInfo(int HeaderOffset, int DataOffset, int CiphertextLength, bool IsFinal, int PlaintextLength);

    private readonly List<ChunkInfo> _chunks = new();
    private ReadOnlyMemory<byte> _headerBytes;
    private ReadOnlyMemory<byte> _footerBytes;

    public PqfFileHeader Header { get; private set; } = null!;
    public ReadOnlyMemory<byte> HeaderSignatureBytes { get; private set; }
    public ReadOnlyMemory<byte> FileSignatureBytes { get; private set; }
    public ulong TotalChunkCount { get; private set; }
    public ulong ReportedPlaintextBytes { get; private set; }
    public ReadOnlyMemory<byte> FileBytes { get; private set; }
    internal ReadOnlyMemory<byte> HeaderBytes => _headerBytes;
    internal ReadOnlyMemory<byte> FooterBytes => _footerBytes;
    internal IReadOnlyList<ChunkInfo> Chunks => _chunks;

    /// <summary>
    /// Open and validate a PQF file for reading.
    /// Throws PqfFileException on any refusal condition.
    /// This API validates a fully materialized byte buffer and currently uses
    /// int-indexed offsets internally, so its practical ceiling is bounded by
    /// the size of a single in-memory buffer on the current runtime.
    /// </summary>
    public static PqfFileReader OpenForValidation(ReadOnlyMemory<byte> fileBytes)
    {
        var reader = new PqfFileReader();
        reader.ValidateAndParse(fileBytes);
        return reader;
    }

    public static async Task DecryptAsync(
        Stream source,
        Stream destination,
        PqfIdentity identity,
        ICryptoProvider? provider = null,
        CancellationToken cancellationToken = default)
    {
        if (provider is null)
        {
            await PqfDecryptor.DecryptAsync(source, destination, identity, cancellationToken).ConfigureAwait(false);
            return;
        }

        var decryptor = new AuthenticatedModeDecryptor();
        await decryptor.DecryptAsync(source, destination, identity, provider, cancellationToken).ConfigureAwait(false);
    }

    private void ValidateAndParse(ReadOnlyMemory<byte> fileBytes)
    {
        FileBytes = fileBytes;
        var bytes = fileBytes.Span;

        // Offset 0: Magic "PQF1" (4 bytes)
        if (bytes.Length < 4 || !bytes[..4].SequenceEqual("PQF1"u8))
        {
            throw new PqfFileException(
                PqfRefusalReason.MagicMismatch,
                "File magic mismatch: expected 'PQF1'",
                offset: 0);
        }

        // Offset 4: Version 0x0001 (uint16 BE)
        if (bytes.Length < 6)
        {
            throw new PqfFileException(
                PqfRefusalReason.TruncationDetected,
                "File truncated before version field",
                offset: 4);
        }

        var version = BinaryPrimitives.ReadUInt16BigEndian(bytes[4..6]);
        if (version != PqfVersion)
        {
            throw new PqfFileException(
                PqfRefusalReason.VersionMismatch,
                $"Version mismatch: expected {PqfVersion:X4}, got {version:X4}",
                offset: 4);
        }

        // Offset 6: Header length (uint32 BE)
        if (bytes.Length < 10)
        {
            throw new PqfFileException(
                PqfRefusalReason.TruncationDetected,
                "File truncated before header length field",
                offset: 6);
        }

        var headerLength = BinaryPrimitives.ReadUInt32BigEndian(bytes[6..10]);
        if (headerLength == 0 || headerLength > MaxHeaderLength)
        {
            throw new PqfFileException(
                PqfRefusalReason.HeaderLengthExceedsLimit,
                $"Header length invalid: {headerLength} (must be 1-{MaxHeaderLength})",
                offset: 6);
        }

        // Extract header CBOR bytes
        if (bytes.Length < 10 + headerLength)
        {
            throw new PqfFileException(
                PqfRefusalReason.TruncationDetected,
                $"File truncated: expected {10 + headerLength} bytes, got {bytes.Length}",
                offset: 10);
        }

        var headerCborBytes = fileBytes.Slice(10, (int)headerLength);
        _headerBytes = headerCborBytes;

        // Validate CBOR determinism once, then pass the parsed value into the
        // schema reader.
        CborValue headerValue;
        try
        {
            headerValue = DeterministicCborValidator.ParseStrict(headerCborBytes);
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
                var msg when msg.Contains("floating") => PqfRefusalReason.NonDeterministicCborEncoding,
                _ => PqfRefusalReason.NonDeterministicCborEncoding,
            };
            throw new PqfFileException(reason, $"CBOR validation failed: {ex.Message}", offset: 10);
        }
        catch (PqfFileException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new PqfFileException(
                PqfRefusalReason.NonDeterministicCborEncoding,
                $"CBOR parsing failed: {ex.Message}",
                offset: 10);
        }

        // Parse and validate header schema
        try
        {
            this.Header = HeaderCborReader.Parse(headerValue);
        }
        catch (PqfFileException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new PqfFileException(
                PqfRefusalReason.NonDeterministicCborEncoding,
                $"Header schema parsing failed: {ex.Message}");
        }

        var currentOffset = 10 + (int)headerLength;

        // Validate signature structural presence/absence
        if (this.Header.Signer != null)
        {
            // Signed file: must have both signatures (4691 bytes each)
            if (bytes.Length < currentOffset + HybridSignatureLength)
            {
                throw new PqfFileException(
                    PqfRefusalReason.TruncationDetected,
                    "Signed file missing header signature (4691 bytes)",
                    offset: currentOffset);
            }

            this.HeaderSignatureBytes = fileBytes.Slice(currentOffset, HybridSignatureLength);
            currentOffset += HybridSignatureLength;
        }

        var trailingBytesNeeded = 20 + (this.Header.Signer != null ? HybridSignatureLength : 0);
        if (bytes.Length < currentOffset + trailingBytesNeeded)
        {
            throw new PqfFileException(
                PqfRefusalReason.TruncationDetected,
                "File truncated before footer/signature section",
                offset: currentOffset);
        }

        var payloadEnd = bytes.Length - trailingBytesNeeded;
        ParseChunks(fileBytes, ref currentOffset, payloadEnd);

        if (currentOffset != payloadEnd)
        {
            throw new PqfFileException(
                PqfRefusalReason.TrailingDataAfterExpectedEof,
                "Trailing chunk data found before footer",
                offset: currentOffset);
        }

        var footerOffset = payloadEnd;
        var footerSpan = bytes.Slice(footerOffset, 20);
        _footerBytes = fileBytes.Slice(footerOffset, 20);

        // Validate footer magic
        if (!footerSpan[..4].SequenceEqual("PQFE"u8))
        {
            throw new PqfFileException(
                PqfRefusalReason.FooterMagicInvalid,
                "Footer magic mismatch: expected 'PQFE'",
                offset: footerOffset);
        }

        // Parse footer: chunk count and plaintext bytes.
        var chunkCount = BinaryPrimitives.ReadUInt64BigEndian(footerSpan[4..12]);
        var plaintextBytes = BinaryPrimitives.ReadUInt64BigEndian(footerSpan[12..20]);

        this.TotalChunkCount = chunkCount;
        this.ReportedPlaintextBytes = plaintextBytes;

        if (chunkCount != (ulong)_chunks.Count)
        {
            throw new PqfFileException(
                PqfRefusalReason.FooterChunkCountMismatch,
                $"Footer chunk count mismatch: expected {chunkCount}, observed {_chunks.Count}",
                offset: footerOffset + 4);
        }

        ulong observedPlaintextBytes = 0;
        foreach (var chunk in _chunks)
        {
            observedPlaintextBytes += (ulong)chunk.PlaintextLength;
        }

        if (plaintextBytes != observedPlaintextBytes)
        {
            throw new PqfFileException(
                PqfRefusalReason.FooterPlaintextBytesMismatch,
                $"Footer plaintext bytes mismatch: expected {plaintextBytes}, observed {observedPlaintextBytes}",
                offset: footerOffset + 12);
        }

        currentOffset = footerOffset + 20;

        // Validate file signature if signed
        if (this.Header.Signer != null)
        {
            if (bytes.Length < currentOffset + HybridSignatureLength)
            {
                throw new PqfFileException(
                    PqfRefusalReason.TruncationDetected,
                    "Signed file missing file signature (4691 bytes)",
                    offset: currentOffset);
            }

            this.FileSignatureBytes = fileBytes.Slice(currentOffset, HybridSignatureLength);
            currentOffset += HybridSignatureLength;
        }

        // Verify EOF
        if (bytes.Length != currentOffset)
        {
            throw new PqfFileException(
                PqfRefusalReason.TrailingDataAfterExpectedEof,
                $"File has trailing data: {bytes.Length - currentOffset} extra bytes",
                offset: currentOffset);
        }

    }

    private void ParseChunks(ReadOnlyMemory<byte> fileBytes, ref int offset, int payloadEnd)
    {
        var bytes = fileBytes.Span;
        _chunks.Clear();
        var sawFinal = false;

        while (offset < payloadEnd)
        {
            if (payloadEnd - offset < 5)
            {
                throw new PqfFileException(
                    PqfRefusalReason.TruncationDetected,
                    "Chunk header truncated",
                    offset: offset);
            }

            var chunkHeaderOffset = offset;
            var ciphertextLength = (int)BinaryPrimitives.ReadUInt32BigEndian(bytes.Slice(offset, 4));
            var flags = bytes[offset + 4];
            var isFinal = (flags & 0x01) != 0;

            if ((flags & 0xFE) != 0)
            {
                throw new PqfFileException(
                    PqfRefusalReason.ReservedChunkFlagBitsSet,
                    "Reserved chunk flag bits must be zero",
                    offset: offset + 4);
            }

            offset += 5;

            if (ciphertextLength < 16)
            {
                throw new PqfFileException(
                    PqfRefusalReason.TruncationDetected,
                    "Chunk ciphertext must include at least a 16-byte AES-GCM tag",
                    offset: chunkHeaderOffset);
            }

            if (ciphertextLength > payloadEnd - offset)
            {
                throw new PqfFileException(
                    PqfRefusalReason.ChunkLengthExceedsRemainingBytes,
                    "Chunk length exceeds remaining payload bytes",
                    offset: chunkHeaderOffset);
            }

            var dataOffset = offset;
            var plaintextLength = ciphertextLength - 16;

            _chunks.Add(new ChunkInfo(
                HeaderOffset: chunkHeaderOffset,
                DataOffset: dataOffset,
                CiphertextLength: ciphertextLength,
                IsFinal: isFinal,
                PlaintextLength: plaintextLength));

            offset += ciphertextLength;

            if (isFinal)
            {
                sawFinal = true;
                break;
            }
        }

        if (_chunks.Count > 0 && !sawFinal)
        {
            throw new PqfFileException(
                PqfRefusalReason.TrailingDataAfterExpectedEof,
                "No final chunk flag found before footer",
                offset: offset);
        }

        if (sawFinal && offset != payloadEnd)
        {
            throw new PqfFileException(
                PqfRefusalReason.TrailingDataAfterExpectedEof,
                "Data found between final chunk and footer",
                offset: offset);
        }
    }
}
