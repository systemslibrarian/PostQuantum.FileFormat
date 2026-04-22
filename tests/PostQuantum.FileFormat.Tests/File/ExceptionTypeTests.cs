using PostQuantum.FileFormat.File;

namespace PostQuantum.FileFormat.Tests.File;

public sealed class ExceptionTypeTests
{
    [Fact]
    public void PqfFileException_construct_with_reason_message_offset()
    {
        var reason = PqfRefusalReason.MagicMismatch;
        var message = "Unexpected magic bytes";
        long offset = 0;

        var ex = new PqfFileException(reason, message, offset);

        Assert.Equal(reason, ex.Reason);
        Assert.Equal(message, ex.Message);
        Assert.Equal(offset, ex.Offset);
    }

    [Fact]
    public void PqfFileException_construct_with_null_offset()
    {
        var reason = PqfRefusalReason.HeaderLengthExceedsLimit;
        var message = "Header exceeds 1 MiB limit";

        var ex = new PqfFileException(reason, message);

        Assert.Equal(reason, ex.Reason);
        Assert.Null(ex.Offset);
    }

    [Fact]
    public void PqfRefusalReason_contains_all_required_values()
    {
        var reasons = typeof(PqfRefusalReason).GetEnumValues().Cast<PqfRefusalReason>().ToList();
        
        Assert.Contains(PqfRefusalReason.MagicMismatch, reasons);
        Assert.Contains(PqfRefusalReason.VersionMismatch, reasons);
        Assert.Contains(PqfRefusalReason.HeaderLengthExceedsLimit, reasons);
        Assert.Contains(PqfRefusalReason.NonDeterministicCborEncoding, reasons);
        Assert.Contains(PqfRefusalReason.DuplicateCborKey, reasons);
        Assert.Contains(PqfRefusalReason.TruncationDetected, reasons);
    }
}
