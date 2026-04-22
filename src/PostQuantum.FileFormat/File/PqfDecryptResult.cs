namespace PostQuantum.FileFormat.File;

[MustUseReturnValue]
public sealed class PqfDecryptResult
{
    public PqfDecryptResult(bool success, PqfRefusalReason? failureReason, long plaintextBytesEmitted, bool postHocAuthenticationFailed)
    {
        Success = success;
        FailureReason = failureReason;
        PlaintextBytesEmitted = plaintextBytesEmitted;
        PostHocAuthenticationFailed = postHocAuthenticationFailed;
    }

    public bool Success { get; }

    public PqfRefusalReason? FailureReason { get; }

    public long PlaintextBytesEmitted { get; }

    public bool PostHocAuthenticationFailed { get; }

    public void ThrowIfFailed()
    {
        if (Success)
        {
            return;
        }

        if (FailureReason is null)
        {
            throw new PqfFileException(PqfRefusalReason.AeadTagFailure, "Decryption failed");
        }

        throw new PqfFileException(FailureReason.Value, "Streaming decryption failed");
    }
}
