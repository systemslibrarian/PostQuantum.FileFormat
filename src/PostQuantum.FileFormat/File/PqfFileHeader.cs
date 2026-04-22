namespace PostQuantum.FileFormat.File;

/// <summary>
/// Parsed PQF file header representation. Holds validated header data but
/// does not perform cryptographic operations (those are Phase 3+).
/// </summary>
public sealed class PqfFileHeader
{
    public string? SignatureAlgorithm { get; set; }
    public System.Collections.Generic.List<PqfRecipientBlock> Recipients { get; set; } = new();
    public PqfSignerBlock? Signer { get; set; }
    public uint ChunkSize { get; set; }
    public System.DateTime CreatedUtc { get; set; }
    public byte[] FileId { get; set; } = Array.Empty<byte>();
}
