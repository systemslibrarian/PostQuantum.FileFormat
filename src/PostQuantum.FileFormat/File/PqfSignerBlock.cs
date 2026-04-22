namespace PostQuantum.FileFormat.File;

public sealed class PqfSignerBlock
{
    public byte[] ClassicalPub { get; set; } = Array.Empty<byte>();
    public byte[] PqcPub { get; set; } = Array.Empty<byte>();
}
