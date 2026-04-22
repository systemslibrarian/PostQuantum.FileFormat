namespace PostQuantum.FileFormat.File;

public enum PqfRefusalReason
{
    MagicMismatch,
    VersionMismatch,
    HeaderLengthExceedsLimit,
    NonDeterministicCborEncoding,
    UnknownHeaderField,
    MissingRequiredField,
    AlgorithmIdentifierMismatch,
    ChunkSizeInvalid,
    CreatedTimestampInvalid,
    RecipientsEmpty,
    BinaryFieldLengthMismatch,
    IdentityMatchesNoRecipient,
    SignatureVerificationFailure,
    AeadTagFailure,
    FooterChunkCountMismatch,
    FooterPlaintextBytesMismatch,
    FooterMagicInvalid,
    ReservedChunkFlagBitsSet,
    ChunkLengthExceedsRemainingBytes,
    TruncationDetected,
    TrailingDataAfterExpectedEof,
    DuplicateCborKey,
    SignerPresenceMismatch,
}
