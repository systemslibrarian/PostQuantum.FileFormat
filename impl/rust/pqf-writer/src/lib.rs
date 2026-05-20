//! Independent Rust writer for the PQF v1 file format.
//!
//! **Status: scaffold.** The structure and the deterministic-CBOR header
//! builder are implemented in this crate. The cryptographic operations
//! (X25519/ML-KEM encapsulation, HKDF combiner, AES-GCM wrap and chunked
//! AEAD, hybrid signing) live behind clearly-marked TODOs and are the
//! next contribution surface. The reader crate alongside this one is
//! complete and validates anything produced here, so a contributor can
//! work iteratively against a working oracle.
//!
//! Why a Rust writer at all? The cross-impl conformance gate that the
//! reader provides is one-directional today: Rust reads .NET. Adding a
//! writer here closes the loop — the .NET reader can then validate
//! Rust's encoder output, catching divergence that no single-impl test
//! can.
//!
//! Scope this crate is not trying to cover yet:
//!   - Hybrid signing. Reader supports verification; writer signing is TODO.
//!   - Streaming encrypt of files that don't fit in memory.
//!   - Constant-time wrappers around the RustCrypto primitive calls.
//!     (The reader has the same caveat — see docs/SIDE-CHANNEL-POSTURE.md.)

#![allow(dead_code)]

pub mod cbor_build;
pub mod error;

pub use error::{WriterError, WriterResult};

/// Build the deterministic CBOR header bytes for a PQF v1 file with the
/// given inputs. This is fully implemented; it does NOT depend on any
/// cryptographic operation and is suitable for unit-testing against the
/// .NET reference encoder.
pub fn build_header_bytes(
    file_id: [u8; 16],
    chunk_size: u32,
    created_rfc3339: &str,
    recipients: &[RecipientMaterial],
    signer: Option<&SignerMaterial>,
) -> WriterResult<Vec<u8>> {
    cbor_build::build_header(file_id, chunk_size, created_rfc3339, recipients, signer)
}

/// Per-recipient material the writer needs to produce one entry of the
/// header's `recipients` array. The encrypt-and-wrap step that produces
/// these from a recipient public key is part of the TODO surface.
pub struct RecipientMaterial {
    pub classical_epk: [u8; 32],
    pub pqc_ct: Vec<u8>, // 1568 bytes for ML-KEM-1024
    pub wrapped_dek: Vec<u8>, // 48 bytes
    pub wrapped_dek_nonce: [u8; 12],
}

/// Signer public key material.
pub struct SignerMaterial {
    pub classical_pub: [u8; 32],
    pub pqc_pub: Vec<u8>, // 2592 bytes for ML-DSA-87
}

/// TODO: the full encrypt path. The signature is the goal-state surface;
/// the current implementation returns NotYetImplemented so callers can
/// thread it through their pipelines while the body is filled in.
pub fn encrypt_to_bytes(
    _plaintext: &[u8],
    _recipients_pub: &[ReaderPublicKey],
    _chunk_size: u32,
) -> WriterResult<Vec<u8>> {
    Err(WriterError::NotYetImplemented(
        "encrypt_to_bytes: scaffold-only — see crate docs for what is/isn't implemented",
    ))
}

/// Imported recipient public key (canonical 1601-byte form used in
/// the reader's manifest).
pub struct ReaderPublicKey {
    pub bytes: Vec<u8>,
}
