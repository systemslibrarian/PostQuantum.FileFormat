using System.Buffers.Binary;

namespace PostQuantum.FileFormat.File;

/// <summary>
/// Parsed PQF file footer from the 20-byte footer structure (§5.5).
/// </summary>
public sealed class PqfFooter
{
    public long TotalChunkCount { get; set; }
    public long TotalPlaintextBytes { get; set; }
}
