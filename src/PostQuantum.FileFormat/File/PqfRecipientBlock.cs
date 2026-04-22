namespace PostQuantum.FileFormat.File;

public sealed class PqfRecipientBlock
{
    public byte[] ClassicalEpk { get; set; } = Array.Empty<byte>();
    public byte[] PqcCt { get; set; } = Array.Empty<byte>();
    public byte[] WrappedDek { get; set; } = Array.Empty<byte>();
    public byte[] WrappedDekNonce { get; set; } = Array.Empty<byte>();
}
