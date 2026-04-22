using PostQuantum.FileFormat.File;

namespace PostQuantum.FileFormat.Tests.File;

public sealed class HeaderParser_RefusalTests
{
    [Fact]
    public void Reader_refuses_wrong_magic()
    {
        var bytes = SampleFiles.BuildMalformed_WrongMagic();
        var ex = Assert.Throws<PqfFileException>(() => PqfFileReader.OpenForValidation(bytes));
        Assert.Equal(PqfRefusalReason.MagicMismatch, ex.Reason);
        Assert.Equal(0, ex.Offset);
    }

    [Fact]
    public void Reader_refuses_wrong_version()
    {
        var bytes = SampleFiles.BuildMalformed_WrongVersion();
        var ex = Assert.Throws<PqfFileException>(() => PqfFileReader.OpenForValidation(bytes));
        Assert.Equal(PqfRefusalReason.VersionMismatch, ex.Reason);
        Assert.Equal(4, ex.Offset);
    }

    [Fact]
    public void Reader_refuses_header_length_exceeds_1_mib()
    {
        var bytes = SampleFiles.BuildMalformed_HeaderLengthTooLarge();
        var ex = Assert.Throws<PqfFileException>(() => PqfFileReader.OpenForValidation(bytes));
        Assert.Equal(PqfRefusalReason.HeaderLengthExceedsLimit, ex.Reason);
        Assert.Equal(6, ex.Offset);
    }

    [Fact]
    public void Reader_refuses_header_length_zero()
    {
        var bytes = SampleFiles.BuildMalformed_HeaderLengthZero();
        var ex = Assert.Throws<PqfFileException>(() => PqfFileReader.OpenForValidation(bytes));
        Assert.Equal(PqfRefusalReason.HeaderLengthExceedsLimit, ex.Reason);
        Assert.Equal(6, ex.Offset);
    }

    [Fact]
    public void Reader_refuses_truncation_before_full_header_length()
    {
        var bytes = SampleFiles.BuildMalformed_Truncated_BeforeHeader();
        var ex = Assert.Throws<PqfFileException>(() => PqfFileReader.OpenForValidation(bytes));
        Assert.Equal(PqfRefusalReason.TruncationDetected, ex.Reason);
    }
}
