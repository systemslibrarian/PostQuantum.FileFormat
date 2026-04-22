using PostQuantum.FileFormat.File;

namespace PostQuantum.FileFormat.Tests.File;

public sealed class ProcessingModeRefusalTests
{
    [Fact]
    public void Decrypt_result_throw_if_failed_throws_exception_with_reason()
    {
        var result = new PqfDecryptResult(
            success: false,
            failureReason: PqfRefusalReason.SignatureVerificationFailure,
            plaintextBytesEmitted: 1024,
            postHocAuthenticationFailed: true);

        var ex = Assert.Throws<PqfFileException>(() => result.ThrowIfFailed());
        Assert.Equal(PqfRefusalReason.SignatureVerificationFailure, ex.Reason);
    }

    [Fact]
    public void Decrypt_result_throw_if_failed_noop_on_success()
    {
        var result = new PqfDecryptResult(
            success: true,
            failureReason: null,
            plaintextBytesEmitted: 10,
            postHocAuthenticationFailed: false);

        result.ThrowIfFailed();
    }
}
