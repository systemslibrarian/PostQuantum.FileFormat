//! Independent Rust writer for the PQF v1 file format.
//!
//! This crate now implements the **full unsigned-encrypt path** in
//! Rust as a second-source for the .NET reference writer. The
//! cross-impl differential gate (CI: `differential-bidirectional.yml`)
//! is what validates correctness: a container produced here is
//! consumed by the .NET reference reader on every push, and any
//! divergence is a wire-format defect.
//!
//! What's implemented today:
//!   - X25519 ephemeral keygen + ECDH with each recipient's classical pub.
//!   - ML-KEM-1024 encapsulation against each recipient's PQ pub.
//!   - HKDF-Extract combiner producing per-recipient KEK
//!     (`pqf1-concat-extract-v1`, spec §2.4).
//!   - AES-256-GCM wrap of the per-file DEK under each recipient KEK.
//!   - Per-chunk HKDF-Expand derived chunk keys; AES-256-GCM with the
//!     fixed zero nonce and AAD bound to `file_id || idx || is_final`.
//!   - Footer construction with chunk_count + plaintext_bytes.
//!   - Deterministic CBOR header build (RFC 8949 §4.2.2).
//!
//! What is NOT yet implemented:
//!   - Hybrid signing (Ed25519 + ML-DSA-87). Reader supports
//!     verification; writer signing is the next contribution.
//!   - Streaming encrypt for plaintexts that don't fit in memory.
//!   - Constant-time wrappers around the RustCrypto primitive calls.
//!     (The reader has the same caveat; see docs/SIDE-CHANNEL-POSTURE.md.)

#![allow(dead_code)]

pub mod cbor_build;
pub mod error;

pub use error::{WriterError, WriterResult};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use ml_kem::kem::Encapsulate;
use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem1024};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey as XPub};

// Format constants — must match impl/rust/pqf-reader/src/reader.rs and the
// .NET reference implementation byte-for-byte.
const PQF_MAGIC: [u8; 4] = *b"PQF1";
const PQF_VERSION: u16 = 0x0001;
const FOOTER_MAGIC: [u8; 4] = *b"PQFE";
const FOOTER_LEN: usize = 20;
const COMBINER_SALT_PREFIX: &[u8] = b"PQF1-combiner-v1";
const KEK_INFO: &[u8] = b"PQF1-kek-v1";
const CHUNK_INFO_PREFIX: &[u8] = b"PQF1-chunk-v1";

const X25519_PK_LEN: usize = 32;
const MLKEM_PK_LEN: usize = 1568;
const PUBKEY_VERSION: u8 = 0x01;
const PUBKEY_TOTAL_LEN: usize = 1 + X25519_PK_LEN + MLKEM_PK_LEN;

/// A recipient public key in the canonical 1601-byte form:
/// `0x01 || x25519_pub(32) || mlkem_1024_pub(1568)`.
#[derive(Clone)]
pub struct RecipientPublicKey {
    pub canonical: Vec<u8>,
}

impl RecipientPublicKey {
    pub fn from_canonical(bytes: &[u8]) -> WriterResult<Self> {
        if bytes.len() != PUBKEY_TOTAL_LEN {
            return Err(WriterError::RecipientFieldLength {
                field: "public_key",
                got: bytes.len(),
                want: PUBKEY_TOTAL_LEN,
            });
        }
        if bytes[0] != PUBKEY_VERSION {
            return Err(WriterError::RecipientFieldLength {
                field: "public_key.version",
                got: bytes[0] as usize,
                want: PUBKEY_VERSION as usize,
            });
        }
        Ok(Self { canonical: bytes.to_vec() })
    }

    fn x25519_pub(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.canonical[1..1 + X25519_PK_LEN]);
        out
    }
    fn mlkem_pub(&self) -> &[u8] {
        &self.canonical[1 + X25519_PK_LEN..]
    }
}

/// Encrypt `plaintext` to the given recipients, producing a complete
/// unsigned PQF v1 container.
///
/// `chunk_size` must be a power of two in `[4096, 16777216]`. The
/// container is fully materialized in memory (an `Vec<u8>`); streaming
/// encrypt for plaintexts that do not fit in memory is future work.
pub fn encrypt_to_bytes(
    plaintext: &[u8],
    recipients: &[RecipientPublicKey],
    chunk_size: u32,
) -> WriterResult<Vec<u8>> {
    if recipients.is_empty() {
        return Err(WriterError::NotYetImplemented(
            "encrypt_to_bytes: at least one recipient is required",
        ));
    }
    if !(chunk_size >= 4096 && chunk_size <= 16_777_216 && chunk_size.is_power_of_two()) {
        return Err(WriterError::InvalidChunkSize(chunk_size));
    }

    // Per-file material.
    let mut rng = OsRng;
    let mut file_id = [0u8; 16];
    rng.fill_bytes(&mut file_id);
    let mut dek = [0u8; 32];
    rng.fill_bytes(&mut dek);

    // Build recipient blocks: per-recipient (epk, ct, wrapped_dek, nonce).
    let mut recipient_materials: Vec<RecipientMaterial> = Vec::with_capacity(recipients.len());
    for (idx, r) in recipients.iter().enumerate() {
        recipient_materials.push(build_recipient_block(idx as u32, &file_id, &dek, r)?);
    }

    // Header. Today: no signer (signing-writer is the next deliverable).
    let created = current_rfc3339_utc();
    let header_bytes = cbor_build::build_header(
        file_id,
        chunk_size,
        &created,
        &recipient_materials,
        None,
    )?;

    // Assemble: magic + version + header_len + header + chunks + footer.
    let mut out = Vec::with_capacity(plaintext.len() + 4096);
    out.extend_from_slice(&PQF_MAGIC);
    out.extend_from_slice(&PQF_VERSION.to_be_bytes());
    out.extend_from_slice(&(header_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&header_bytes);

    // Chunked AEAD.
    let chunk_sz = chunk_size as usize;
    let total_chunks: u64 = if plaintext.is_empty() {
        0
    } else {
        ((plaintext.len() + chunk_sz - 1) / chunk_sz) as u64
    };

    let mut offset = 0usize;
    let mut chunk_idx: u64 = 0;
    while offset < plaintext.len() {
        let end = (offset + chunk_sz).min(plaintext.len());
        let is_final = end == plaintext.len();
        let chunk_pt = &plaintext[offset..end];

        // Per-chunk key.
        let mut info = Vec::with_capacity(CHUNK_INFO_PREFIX.len() + 8);
        info.extend_from_slice(CHUNK_INFO_PREFIX);
        info.extend_from_slice(&chunk_idx.to_be_bytes());
        let hk = Hkdf::<Sha256>::from_prk(&dek)
            .map_err(|_| WriterError::NotYetImplemented("HKDF init for chunk key failed"))?;
        let mut chunk_key = [0u8; 32];
        hk.expand(&info, &mut chunk_key)
            .map_err(|_| WriterError::NotYetImplemented("HKDF expand for chunk key failed"))?;

        // AAD.
        let mut aad = Vec::with_capacity(16 + 8 + 1);
        aad.extend_from_slice(&file_id);
        aad.extend_from_slice(&chunk_idx.to_be_bytes());
        aad.push(if is_final { 1 } else { 0 });

        // Encrypt with fixed zero nonce (safe because chunk_key is unique per chunk).
        let cipher = Aes256Gcm::new_from_slice(&chunk_key).expect("32-byte key");
        let nonce = Nonce::from_slice(&[0u8; 12]);
        let ct = cipher
            .encrypt(nonce, Payload { msg: chunk_pt, aad: &aad })
            .map_err(|_| WriterError::NotYetImplemented("AEAD encrypt failed"))?;

        // Frame: 1 byte flags, 4 bytes BE length, ciphertext+tag.
        let flags: u8 = if is_final { 0x01 } else { 0x00 };
        out.push(flags);
        out.extend_from_slice(&(ct.len() as u32).to_be_bytes());
        out.extend_from_slice(&ct);

        offset = end;
        chunk_idx += 1;
    }

    // Footer.
    out.extend_from_slice(&FOOTER_MAGIC);
    out.extend_from_slice(&total_chunks.to_be_bytes());
    out.extend_from_slice(&(plaintext.len() as u64).to_be_bytes());

    // Zeroize DEK before returning. The chunk_key copies are short-lived.
    for b in dek.iter_mut() { *b = 0; }

    Ok(out)
}

/// Material for one entry of the header's `recipients` array, paired with
/// the values needed to re-emit it later.
pub struct RecipientMaterial {
    pub classical_epk: [u8; 32],
    pub pqc_ct: Vec<u8>,
    pub wrapped_dek: Vec<u8>,
    pub wrapped_dek_nonce: [u8; 12],
}

/// Signer public key material (placeholder; signing path TODO).
pub struct SignerMaterial {
    pub classical_pub: [u8; 32],
    pub pqc_pub: Vec<u8>,
}

fn build_recipient_block(
    idx: u32,
    file_id: &[u8; 16],
    dek: &[u8; 32],
    recipient: &RecipientPublicKey,
) -> WriterResult<RecipientMaterial> {
    // Ephemeral X25519 -> classical shared secret.
    let eph_sec = EphemeralSecret::random_from_rng(&mut OsRng);
    let epk = XPub::from(&eph_sec);
    let peer_xpub = XPub::from(recipient.x25519_pub());
    let ss_classical = eph_sec.diffie_hellman(&peer_xpub);

    // ML-KEM-1024 encapsulation -> PQ shared secret + ciphertext.
    let mlkem_pk_bytes = recipient.mlkem_pub();
    let encoded: &Encoded<<MlKem1024 as KemCore>::EncapsulationKey> = mlkem_pk_bytes
        .try_into()
        .map_err(|_| WriterError::RecipientFieldLength {
            field: "ml_kem_1024_public_key",
            got: mlkem_pk_bytes.len(),
            want: MLKEM_PK_LEN,
        })?;
    let ek = <<MlKem1024 as KemCore>::EncapsulationKey as EncodedSizeUser>::from_bytes(encoded);
    let (ct_arr, ss_pqc) = ek
        .encapsulate(&mut OsRng)
        .map_err(|_| WriterError::NotYetImplemented("ML-KEM-1024 encapsulate failed"))?;
    let pqc_ct: Vec<u8> = ct_arr.as_slice().to_vec();

    // KEK = HKDF-Extract over (ss_classical || ss_pqc) with salt
    // = COMBINER_SALT_PREFIX || file_id || idx_be32, then HKDF-Expand with KEK_INFO.
    let mut salt = Vec::with_capacity(COMBINER_SALT_PREFIX.len() + 16 + 4);
    salt.extend_from_slice(COMBINER_SALT_PREFIX);
    salt.extend_from_slice(file_id);
    salt.extend_from_slice(&idx.to_be_bytes());

    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(ss_classical.as_bytes());
    ikm[32..].copy_from_slice(ss_pqc.as_slice());

    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut kek = [0u8; 32];
    hk.expand(KEK_INFO, &mut kek)
        .map_err(|_| WriterError::NotYetImplemented("HKDF expand for KEK failed"))?;

    // Wrap DEK with AES-256-GCM, AAD = file_id, fresh random nonce.
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(&kek).expect("KEK is 32 bytes");
    let nonce = Nonce::from_slice(&nonce_bytes);
    let wrapped = cipher
        .encrypt(nonce, Payload { msg: dek, aad: file_id })
        .map_err(|_| WriterError::NotYetImplemented("DEK wrap failed"))?;

    // Zeroize sensitive intermediates.
    for b in ikm.iter_mut() { *b = 0; }
    for b in kek.iter_mut() { *b = 0; }

    Ok(RecipientMaterial {
        classical_epk: *epk.as_bytes(),
        pqc_ct,
        wrapped_dek: wrapped,
        wrapped_dek_nonce: nonce_bytes,
    })
}

fn current_rfc3339_utc() -> String {
    // RFC 3339 datetime in UTC with second precision and trailing 'Z'.
    // We avoid pulling chrono in to keep the dep footprint minimal; the
    // reader treats `created` as text and the .NET writer emits second-
    // precision UTC.
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as i64;
    seconds_to_rfc3339(secs)
}

/// Inline civil-time conversion for Unix-epoch seconds to RFC 3339 UTC.
/// Avoids pulling chrono; correct for the 1970-2099 range that matters
/// for our timestamps.
fn seconds_to_rfc3339(secs_since_epoch: i64) -> String {
    let secs = secs_since_epoch.max(0) as u64;
    let day = secs / 86_400;
    let tod = secs % 86_400;
    let h = tod / 3600;
    let m = (tod % 3600) / 60;
    let s = tod % 60;

    // Civil date from days since 1970-01-01 (Howard Hinnant).
    let z = day as i64 + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let year = if month <= 2 { y + 1 } else { y };
    format!("{year:04}-{month:02}-{d:02}T{h:02}:{m:02}:{s:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_known_values() {
        // 2026-04-21T14:30:00Z = unix seconds 1779719400
        assert_eq!(seconds_to_rfc3339(1_779_719_400), "2026-04-21T14:30:00Z");
        assert_eq!(seconds_to_rfc3339(0), "1970-01-01T00:00:00Z");
    }
}
