using System.Buffers.Binary;
using PostQuantum.FileFormat.Cbor;

namespace PostQuantum.FileFormat.File;

/// <summary>
/// Streaming PQF file parser with fail-closed validation. Validates all structural
/// and schema constraints but defers cryptographic operations to Phase 3+.
/// </summary>
public sealed class PqfFileReader
{
    private const string PqfMagic = "PQF1";
    private const ushort PqfVersion = 0x0001;
    private const uint MaxHeaderLength = 1_048_576; // 1 MiB per spec §3

    public PqfFileHeader Header { get; private set; } = null!;
    public ReadOnlyMemory<byte> HeaderSignatureBytes { get; private set; }
    public ReadOnlyMemory<byte> FileSignatureBytes { get; private set; }
    public long TotalChunkCount { get; private set; }
    public long ReportedPlaintextBytes { get; private set; }

    /// <summary>
    /// Open and validate a PQF file for reading. Validates all structural constraints
    /// but defers decryption and signature verification to Phase 3+.
    /// Throws PqfFileException on any refusal condition.
    /// </summary>
    public static PqfFileReader OpenForValidation(ReadOnlyMemory<byte> fileBytes)
    {
        var reader = new PqfFileReader();
        reader.ValidateAndParse(fileBytes);
        return reader;
    }

    private void ValidateAndParse(ReadOnlyMemory<byte> fileBytes)
    {
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

        // Validate CBOR determinism and parse header
        try
        {
            _ = DeterministicCborValidator.ParseStrict(headerCborBytes);
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
            var headerValue = DeterministicCborValidator.ParseStrict(headerCborBytes);
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

        // Validate signature structural presence/absence
        var currentOffset = 10 + (int)headerLength;
        if (this.Header.Signer != null)
        {
            // Signed file: must have both signatures (4691 bytes each)
            if (bytes.Length < currentOffset + 4691)
            {
                throw new PqfFileException(
                    PqfRefusalReason.TruncationDetected,
                    "Signed file missing header signature (4691 bytes)",
                    offset: currentOffset);
            }

            this.HeaderSignatureBytes = fileBytes.Slice(currentOffset, 4691);
            currentOffset += 4691;
        }

        // Validate footer structure (20 bytes)
        if (bytes.Length < currentOffset + 20)
        {
            throw new PqfFileException(
                PqfRefusalReason.TruncationDetected,
                "File truncated: missing footer (20 bytes)",
                offset: currentOffset);
        }

        var footerOffset = currentOffset;
        var footerSpan = bytes.Slice(footerOffset, 20);

        // Validate footer magic
        if (!footerSpan[..4].SequenceEqual("PQFE"u8))
        {
            throw new PqfFileException(
                PqfRefusalReason.FooterMagicInvalid,
                "Footer magic mismatch: expected 'PQFE'",
                offset: footerOffset);
        }

        // Parse footer: chunk count and plaintext bytes
        var chunkCount = BinaryPrimitives.ReadInt64BigEndian(footerSpan[4..12]);
        var plaintextBytes = BinaryPrimitives.ReadInt64BigEndian(footerSpan[12..20]);

        var footer = new PqfFooter { TotalChunkCount = chunkCount, TotalPlaintextBytes = plaintextBytes };
        this.TotalChunkCount = chunkCount;
        this.ReportedPlaintextBytes = plaintextBytes;

        currentOffset += 20;

        // Validate file signature if signed
        if (this.Header.Signer != null)
        {
            if (bytes.Length < currentOffset + 4691)
            {
                throw new PqfFileException(
                    PqfRefusalReason.TruncationDetected,
                    "Signed file missing file signature (4691 bytes)",
                    offset: currentOffset);
            }

            this.FileSignatureBytes = fileBytes.Slice(currentOffset, 4691);
            currentOffset += 4691;
        }

        // Verify EOF
        if (bytes.Length != currentOffset)
        {
            throw new PqfFileException(
                PqfRefusalReason.TrailingDataAfterExpectedEof,
                $"File has trailing data: {bytes.Length - currentOffset} extra bytes",
                offset: currentOffset);
        }

        // Defer further processing to Phase 3+ (decryption and signature verification)
        throw new NotImplementedException("PHASE 3: Decryption and signature verification");
    }
}
