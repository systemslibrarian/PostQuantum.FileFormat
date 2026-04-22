namespace PostQuantum.FileFormat.File;

public sealed class PqfFileException : Exception
{
    public PqfRefusalReason Reason { get; }
    public long? Offset { get; }

    public PqfFileException(PqfRefusalReason reason, string message, long? offset = null)
        : base(message)
    {
        Reason = reason;
        Offset = offset;
    }
}
