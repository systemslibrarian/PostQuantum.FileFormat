//! Refusal reasons mirrored from the .NET reference implementation's
//! `PqfRefusalReason` enum. The string form (PascalCase) matches the values
//! recorded in `test-vectors/v1/manifest.json` so that the conformance binary
//! can compare reasons across implementations.
//!
//! These names are part of PQF's cross-implementation contract: a conforming
//! reader, when given a vector that the manifest says is `failure` with
//! reason `X`, MUST refuse the file with reason `X` (or a strict-superset
//! reason where the manifest documents that ambiguity is acceptable).
//!
//! When mapping from this Rust reader to the manifest reasons we accept some
//! categorical equivalences that are explicitly identified below — for
//! example a Rust ML-KEM library may produce a different error than the
//! .NET path for an out-of-range PQ ciphertext, but both should ultimately
//! become `IdentityMatchesNoRecipient` after the recipient trial.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalReason {
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

impl RefusalReason {
    pub fn as_pascal_case(self) -> &'static str {
        use RefusalReason::*;
        match self {
            MagicMismatch => "MagicMismatch",
            VersionMismatch => "VersionMismatch",
            HeaderLengthExceedsLimit => "HeaderLengthExceedsLimit",
            NonDeterministicCborEncoding => "NonDeterministicCborEncoding",
            UnknownHeaderField => "UnknownHeaderField",
            MissingRequiredField => "MissingRequiredField",
            AlgorithmIdentifierMismatch => "AlgorithmIdentifierMismatch",
            ChunkSizeInvalid => "ChunkSizeInvalid",
            CreatedTimestampInvalid => "CreatedTimestampInvalid",
            RecipientsEmpty => "RecipientsEmpty",
            BinaryFieldLengthMismatch => "BinaryFieldLengthMismatch",
            IdentityMatchesNoRecipient => "IdentityMatchesNoRecipient",
            SignatureVerificationFailure => "SignatureVerificationFailure",
            AeadTagFailure => "AeadTagFailure",
            FooterChunkCountMismatch => "FooterChunkCountMismatch",
            FooterPlaintextBytesMismatch => "FooterPlaintextBytesMismatch",
            FooterMagicInvalid => "FooterMagicInvalid",
            ReservedChunkFlagBitsSet => "ReservedChunkFlagBitsSet",
            ChunkLengthExceedsRemainingBytes => "ChunkLengthExceedsRemainingBytes",
            TruncationDetected => "TruncationDetected",
            TrailingDataAfterExpectedEof => "TrailingDataAfterExpectedEof",
            DuplicateCborKey => "DuplicateCborKey",
            SignerPresenceMismatch => "SignerPresenceMismatch",
        }
    }
}

impl fmt::Display for RefusalReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_pascal_case())
    }
}

#[derive(Debug)]
pub struct PqfError {
    pub reason: RefusalReason,
    pub message: String,
}

impl PqfError {
    pub fn new(reason: RefusalReason, message: impl Into<String>) -> Self {
        Self {
            reason,
            message: message.into(),
        }
    }
}

impl fmt::Display for PqfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.reason, self.message)
    }
}

impl std::error::Error for PqfError {}

pub type Result<T> = std::result::Result<T, PqfError>;
