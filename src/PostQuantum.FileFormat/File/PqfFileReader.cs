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

        // Defer further parsing to Phase 2.3+ (schema validation, etc.)
        throw new NotImplementedException("PHASE 2.3: Header schema validation not yet implemented");
    }
}
