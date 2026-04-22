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

    [Fact]
    public void Reader_refuses_non_shortest_integer_in_header()
    {
        var bytes = SampleFiles.BuildMalformed_NonShortestIntegerInHeader();
        var ex = Assert.Throws<PqfFileException>(() => PqfFileReader.OpenForValidation(bytes));
        Assert.Equal(PqfRefusalReason.NonDeterministicCborEncoding, ex.Reason);
    }

    [Fact]
    public void Reader_refuses_indefinite_length_map_in_header()
    {
        var bytes = SampleFiles.BuildMalformed_IndefiniteLengthMapInHeader();
        var ex = Assert.Throws<PqfFileException>(() => PqfFileReader.OpenForValidation(bytes));
        Assert.Equal(PqfRefusalReason.NonDeterministicCborEncoding, ex.Reason);
    }

    [Fact]
    public void Reader_refuses_out_of_order_map_keys_in_header()
    {
        var bytes = SampleFiles.BuildMalformed_OutOfOrderMapKeysInHeader();
        var ex = Assert.Throws<PqfFileException>(() => PqfFileReader.OpenForValidation(bytes));
        Assert.Equal(PqfRefusalReason.NonDeterministicCborEncoding, ex.Reason);
    }

    [Fact]
    public void Reader_refuses_duplicate_keys_in_header()
    {
        var bytes = SampleFiles.BuildMalformed_DuplicateKeysInHeader();
        var ex = Assert.Throws<PqfFileException>(() => PqfFileReader.OpenForValidation(bytes));
        Assert.Equal(PqfRefusalReason.DuplicateCborKey, ex.Reason);
    }

    [Fact]
    public void Reader_refuses_floating_point_in_header()
    {
        var bytes = SampleFiles.BuildMalformed_FloatInHeader();
        var ex = Assert.Throws<PqfFileException>(() => PqfFileReader.OpenForValidation(bytes));
        Assert.Equal(PqfRefusalReason.NonDeterministicCborEncoding, ex.Reason);
    }

    [Fact]
    public void Reader_refuses_trailing_bytes_after_cbor_header()
    {
        var bytes = SampleFiles.BuildMalformed_TrailingBytesAfterHeader();
        var ex = Assert.Throws<PqfFileException>(() => PqfFileReader.OpenForValidation(bytes));
        Assert.Equal(PqfRefusalReason.TrailingDataAfterExpectedEof, ex.Reason);
    }
}
