//! Independent Rust writer for the PQF v1 file format.
//!
//! This crate implements the **full unsigned- and signed-encrypt path**
//! in Rust as a second-source for the .NET reference writer. The
//! cross-impl differential gate (CI: `differential-bidirectional.yml`)
//! validates that a container produced here is consumed correctly by
//! the .NET reference reader, and vice versa.
//!
//! What's implemented today:
//!   - X25519 ephemeral keygen + ECDH with each recipient's classical pub.
//!   - ML-KEM-768 encapsulation against each recipient's PQ pub.
//!   - **X-Wing combiner** (draft-connolly-cfrg-xwing-kem):
//!     `KEK = SHA3-256(ss_M || ss_X || ct_X || pk_X || "\.//^\")`.
//!   - AES-256-GCM wrap of the per-file DEK under each recipient KEK
//!     with AAD `file_id (16) || recipient_index (u32 BE)` — preserving
//!     per-file and per-recipient binding that the X-Wing combiner has
//!     no salt slot for.
//!   - Per-chunk HKDF-Expand derived chunk keys; AES-256-GCM with the
//!     fixed zero nonce and AAD bound to `file_id || idx || is_final`.
//!   - Footer construction with chunk_count + plaintext_bytes.
//!   - Deterministic CBOR header build (RFC 8949 §4.2.2).
//!   - Hybrid signing (Ed25519 + ML-DSA-87) when a SigningIdentity is supplied.
//!
//! What is NOT yet implemented:
//!   - Streaming encrypt for plaintexts that don't fit in memory.
//!   - Constant-time wrappers around the RustCrypto primitive calls.
//!     (The reader has the same caveat; see docs/SIDE-CHANNEL-POSTURE.md.)

#![allow(dead_code)]

pub mod cbor_build;
pub mod error;

pub use error::{WriterError, WriterResult};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use ed25519_dalek::{Signer, SigningKey as EdSigningKey};
use hkdf::Hkdf;
use ml_dsa::{MlDsa87, SigningKey as MlDsaSigningKey};
use ml_kem::ml_kem_768::EncapsulationKey as MlKem768Ek;
use ml_kem::{TryKeyInit, B32};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256};
use sha3::Sha3_256;
use x25519_dalek::{EphemeralSecret, PublicKey as XPub};

// Format constants — must match impl/rust/pqf-reader/src/reader.rs and the
// .NET reference implementation byte-for-byte.
const PQF_MAGIC: [u8; 4] = *b"PQF1";
const PQF_VERSION: u16 = 0x0001;
const FOOTER_MAGIC: [u8; 4] = *b"PQFE";
const FOOTER_LEN: usize = 20;

// X-Wing combiner label per draft-connolly-cfrg-xwing-kem (the 6-byte ASCII
// art "\.//^\"). MUST be these exact bytes — NOT the ASCII string "X-Wing".
const XWING_LABEL: [u8; 6] = [0x5C, 0x2E, 0x2F, 0x2F, 0x5E, 0x5C];

// Per-chunk HKDF-Expand label, unrelated to the KEM combiner and unchanged
// from v0.3.x.
const CHUNK_INFO_PREFIX: &[u8] = b"PQF1-chunk-v1";

// Signature-message domain-separation prefixes (spec §6.2). Must
// byte-match the .NET reference HybridSigner.
const HEADER_SIG_DOMAIN: &[u8] = b"PQF1-header-sig-v1";
const FILE_SIG_DOMAIN: &[u8] = b"PQF1-file-sig-v1";

const X25519_PK_LEN: usize = 32;
// ML-KEM-768 public key length per FIPS 203.
const MLKEM_PK_LEN: usize = 1184;
const PUBKEY_VERSION: u8 = 0x01;
const PUBKEY_TOTAL_LEN: usize = 1 + X25519_PK_LEN + MLKEM_PK_LEN;

const ED25519_SIG_LEN: usize = 64;
const MLDSA87_SIG_LEN: usize = 4627;
const HYBRID_SIG_LEN: usize = ED25519_SIG_LEN + MLDSA87_SIG_LEN; // 4691
const MLDSA87_PK_LEN: usize = 2592;
const MLDSA87_SK_LEN: usize = 4896;

/// A recipient public key in the canonical 1217-byte form:
/// `0x01 || x25519_pub(32) || mlkem_768_pub(1184)`.
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
pub fn encrypt_to_bytes(
    plaintext: &[u8],
    recipients: &[RecipientPublicKey],
    chunk_size: u32,
) -> WriterResult<Vec<u8>> {
    encrypt_impl(plaintext, recipients, chunk_size, None)
}

/// Encrypt + hybrid-sign. Signature covers the header bytes and
/// `file_id || sha256(chunks) || footer` respectively.
pub fn encrypt_to_bytes_signed(
    plaintext: &[u8],
    recipients: &[RecipientPublicKey],
    chunk_size: u32,
    signer: &SigningIdentity,
) -> WriterResult<Vec<u8>> {
    encrypt_impl(plaintext, recipients, chunk_size, Some(signer))
}

fn encrypt_impl(
    plaintext: &[u8],
    recipients: &[RecipientPublicKey],
    chunk_size: u32,
    signer: Option<&SigningIdentity>,
) -> WriterResult<Vec<u8>> {
    if recipients.is_empty() {
        return Err(WriterError::NotYetImplemented(
            "encrypt: at least one recipient is required",
        ));
    }
    if !(chunk_size >= 4096 && chunk_size <= 16_777_216 && chunk_size.is_power_of_two()) {
        return Err(WriterError::InvalidChunkSize(chunk_size));
    }

    let mut rng = OsRng;
    let mut file_id = [0u8; 16];
    rng.fill_bytes(&mut file_id);
    let mut dek = [0u8; 32];
    rng.fill_bytes(&mut dek);

    let mut recipient_materials: Vec<RecipientMaterial> = Vec::with_capacity(recipients.len());
    for (idx, r) in recipients.iter().enumerate() {
        recipient_materials.push(build_recipient_block(idx as u32, &file_id, &dek, r)?);
    }

    let created = current_rfc3339_utc();
    let signer_material = signer.map(|s| SignerMaterial {
        classical_pub: s.ed25519_pub,
        pqc_pub: s.mldsa87_pub.clone(),
    });
    let header_bytes = cbor_build::build_header(
        file_id,
        chunk_size,
        &created,
        &recipient_materials,
        signer_material.as_ref(),
    )?;

    let mut out = Vec::with_capacity(plaintext.len() + 8192);
    out.extend_from_slice(&PQF_MAGIC);
    out.extend_from_slice(&PQF_VERSION.to_be_bytes());
    out.extend_from_slice(&(header_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&header_bytes);

    if let Some(s) = signer {
        let mut header_sig_msg = Vec::with_capacity(HEADER_SIG_DOMAIN.len() + header_bytes.len());
        header_sig_msg.extend_from_slice(HEADER_SIG_DOMAIN);
        header_sig_msg.extend_from_slice(&header_bytes);
        let sig = hybrid_sign(s, &header_sig_msg)?;
        out.extend_from_slice(&sig);
    }

    let chunk_sz = chunk_size as usize;
    let total_chunks: u64 = if plaintext.is_empty() {
        0
    } else {
        ((plaintext.len() + chunk_sz - 1) / chunk_sz) as u64
    };
    let mut chunks_hasher = Sha256::new();

    let mut offset = 0usize;
    let mut chunk_idx: u64 = 0;
    while offset < plaintext.len() {
        let end = (offset + chunk_sz).min(plaintext.len());
        let is_final = end == plaintext.len();
        let chunk_pt = &plaintext[offset..end];

        let mut info = Vec::with_capacity(CHUNK_INFO_PREFIX.len() + 8);
        info.extend_from_slice(CHUNK_INFO_PREFIX);
        info.extend_from_slice(&chunk_idx.to_be_bytes());
        let hk = Hkdf::<Sha256>::from_prk(&dek)
            .map_err(|_| WriterError::NotYetImplemented("HKDF init for chunk key failed"))?;
        let mut chunk_key = [0u8; 32];
        hk.expand(&info, &mut chunk_key)
            .map_err(|_| WriterError::NotYetImplemented("HKDF expand for chunk key failed"))?;

        let mut aad = Vec::with_capacity(16 + 8 + 1);
        aad.extend_from_slice(&file_id);
        aad.extend_from_slice(&chunk_idx.to_be_bytes());
        aad.push(if is_final { 1 } else { 0 });

        let cipher = Aes256Gcm::new_from_slice(&chunk_key).expect("32-byte key");
        let nonce = Nonce::from_slice(&[0u8; 12]);
        let ct = cipher
            .encrypt(nonce, Payload { msg: chunk_pt, aad: &aad })
            .map_err(|_| WriterError::NotYetImplemented("AEAD encrypt failed"))?;

        // Chunk frame: length(4 BE) || flags(1) || ciphertext+tag.
        // Spec §5.3. Length-first byte order matches both the .NET writer
        // and the .NET / Rust readers.
        let flags: u8 = if is_final { 0x01 } else { 0x00 };
        let frame_start = out.len();
        out.extend_from_slice(&(ct.len() as u32).to_be_bytes());
        out.push(flags);
        out.extend_from_slice(&ct);
        // The reader's chunks_sha256 covers the full on-disk chunk frame
        // (5-byte prefix + ciphertext+tag).
        chunks_hasher.update(&out[frame_start..]);

        // Zero per-chunk key from the working buffer.
        for b in chunk_key.iter_mut() { *b = 0; }

        offset = end;
        chunk_idx += 1;
    }

    let footer_start = out.len();
    out.extend_from_slice(&FOOTER_MAGIC);
    out.extend_from_slice(&total_chunks.to_be_bytes());
    out.extend_from_slice(&(plaintext.len() as u64).to_be_bytes());
    let footer_bytes: Vec<u8> = out[footer_start..footer_start + FOOTER_LEN].to_vec();

    if let Some(s) = signer {
        let chunks_sha = chunks_hasher.finalize();
        let mut msg = Vec::with_capacity(FILE_SIG_DOMAIN.len() + 16 + 32 + FOOTER_LEN);
        msg.extend_from_slice(FILE_SIG_DOMAIN);
        msg.extend_from_slice(&file_id);
        msg.extend_from_slice(&chunks_sha);
        msg.extend_from_slice(&footer_bytes);
        let sig = hybrid_sign(s, &msg)?;
        out.extend_from_slice(&sig);
    }

    for b in dek.iter_mut() { *b = 0; }
    Ok(out)
}

/// Signing identity (private + public halves of both signing primitives).
pub struct SigningIdentity {
    pub ed25519_sk: [u8; 32],
    pub ed25519_pub: [u8; 32],
    pub mldsa87_sk: Vec<u8>,
    pub mldsa87_pub: Vec<u8>,
}

impl SigningIdentity {
    pub fn from_raw(
        ed25519_sk: [u8; 32],
        ed25519_pub: [u8; 32],
        mldsa87_sk: Vec<u8>,
        mldsa87_pub: Vec<u8>,
    ) -> WriterResult<Self> {
        if mldsa87_pub.len() != MLDSA87_PK_LEN {
            return Err(WriterError::RecipientFieldLength {
                field: "mldsa87_pub",
                got: mldsa87_pub.len(),
                want: MLDSA87_PK_LEN,
            });
        }
        if mldsa87_sk.len() != MLDSA87_SK_LEN {
            return Err(WriterError::RecipientFieldLength {
                field: "mldsa87_sk",
                got: mldsa87_sk.len(),
                want: MLDSA87_SK_LEN,
            });
        }
        Ok(Self { ed25519_sk, ed25519_pub, mldsa87_sk, mldsa87_pub })
    }
}

fn hybrid_sign(signer: &SigningIdentity, message: &[u8]) -> WriterResult<[u8; HYBRID_SIG_LEN]> {
    let ed_sk = EdSigningKey::from_bytes(&signer.ed25519_sk);
    if ed_sk.verifying_key().to_bytes() != signer.ed25519_pub {
        return Err(WriterError::NotYetImplemented(
            "Ed25519 public key does not match the private key",
        ));
    }
    let ed_sig = ed_sk.sign(message).to_bytes();

    let mldsa_sk = decode_mldsa_signing_key(&signer.mldsa87_sk)?;
    let mldsa_sig_obj = mldsa_sk
        .sign_deterministic(message, b"")
        .map_err(|_| WriterError::NotYetImplemented("ML-DSA-87 sign failed"))?;
    let mldsa_sig_bytes = mldsa_sig_obj.encode();
    if mldsa_sig_bytes.len() != MLDSA87_SIG_LEN {
        return Err(WriterError::NotYetImplemented(
            "ML-DSA-87 signature unexpected length",
        ));
    }

    let mut out = [0u8; HYBRID_SIG_LEN];
    out[..ED25519_SIG_LEN].copy_from_slice(&ed_sig);
    out[ED25519_SIG_LEN..].copy_from_slice(&mldsa_sig_bytes);
    Ok(out)
}

fn decode_mldsa_signing_key(bytes: &[u8]) -> WriterResult<MlDsaSigningKey<MlDsa87>> {
    let arr: &[u8; MLDSA87_SK_LEN] = bytes.try_into().map_err(|_| {
        WriterError::RecipientFieldLength {
            field: "mldsa87_sk",
            got: bytes.len(),
            want: MLDSA87_SK_LEN,
        }
    })?;
    let encoded = ml_dsa::EncodedSigningKey::<MlDsa87>::try_from(arr.as_slice()).map_err(|_| {
        WriterError::NotYetImplemented("ML-DSA-87 signing-key encoding parse failed")
    })?;
    Ok(MlDsaSigningKey::<MlDsa87>::decode(&encoded))
}

/// Material for one entry of the header's `recipients` array, paired with
/// the values needed to re-emit it later.
pub struct RecipientMaterial {
    pub classical_epk: [u8; 32],
    pub pqc_ct: Vec<u8>,
    pub wrapped_dek: Vec<u8>,
    pub wrapped_dek_nonce: [u8; 12],
}

/// Signer public key material.
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
    // Ephemeral X25519 -> classical shared secret. epk is X-Wing's ct_X.
    let eph_sec = EphemeralSecret::random_from_rng(&mut OsRng);
    let epk = XPub::from(&eph_sec);
    let peer_xpub = XPub::from(recipient.x25519_pub());
    let ss_classical = eph_sec.diffie_hellman(&peer_xpub);

    // ML-KEM-768 encapsulation -> PQ shared secret + ciphertext.
    let mlkem_pk_bytes = recipient.mlkem_pub();
    let ek = MlKem768Ek::new_from_slice(mlkem_pk_bytes).map_err(|_| {
        WriterError::RecipientFieldLength {
            field: "ml_kem_768_public_key",
            got: mlkem_pk_bytes.len(),
            want: MLKEM_PK_LEN,
        }
    })?;
    // ml-kem 0.3's `encapsulate_with_rng` requires a `CryptoRng` from the
    // newer rand_core version it re-exports — incompatible with the
    // rand 0.8 `OsRng` we use everywhere else. The "hazmat" feature
    // gates `encapsulate_deterministic`, which takes 32 explicit bytes
    // and is cryptographically equivalent to `encapsulate` when those
    // bytes come from a CSPRNG. Fill from rand 0.8's OsRng.
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let seed_b32: B32 = seed.into();
    let (ct_arr, ss_pqc) = ek.encapsulate_deterministic(&seed_b32);
    let pqc_ct: Vec<u8> = ct_arr.as_slice().to_vec();

    // X-Wing combiner per draft-connolly-cfrg-xwing-kem:
    //   KEK = SHA3-256(ss_M || ss_X || ct_X || pk_X || label)
    // where label is the 6-byte literal "\.//^\" (APPENDED, not prepended).
    // An earlier version of this code prepended the label; the
    // X-Wing draft KAT in tests/xwing_draft_kat.rs caught the
    // discrepancy on 2026-05-30.
    let mut sha3 = <Sha3_256 as sha3::Digest>::new();
    sha3.update(ss_pqc.as_slice());          // ss_M (32)
    sha3.update(ss_classical.as_bytes());    // ss_X (32)
    sha3.update(epk.as_bytes());             // ct_X (32)
    sha3.update(&recipient.x25519_pub());    // pk_X (32)
    sha3.update(XWING_LABEL);                // 6 bytes "\.//^\"
    let kek_arr = sha3.finalize();
    let mut kek = [0u8; 32];
    kek.copy_from_slice(&kek_arr);

    // Wrap DEK with AES-256-GCM. AAD binds file instance AND recipient slot;
    // X-Wing's combiner has no salt slot for these so the binding moves
    // here. Nonce is fresh 12 random bytes.
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let mut aad = [0u8; 20];
    aad[..16].copy_from_slice(file_id);
    aad[16..].copy_from_slice(&idx.to_be_bytes());
    let cipher = Aes256Gcm::new_from_slice(&kek).expect("KEK is 32 bytes");
    let nonce = Nonce::from_slice(&nonce_bytes);
    let wrapped = cipher
        .encrypt(nonce, Payload { msg: dek, aad: &aad })
        .map_err(|_| WriterError::NotYetImplemented("DEK wrap failed"))?;

    // Zero sensitive intermediates.
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
        // 2026-05-25T14:30:00Z = unix seconds 1779719400
        assert_eq!(seconds_to_rfc3339(1_779_719_400), "2026-05-25T14:30:00Z");
        assert_eq!(seconds_to_rfc3339(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn xwing_label_is_exactly_the_six_bytes() {
        // draft-connolly-cfrg-xwing-kem: the label is the literal 6-byte
        // ASCII art "\.//^\" (NOT the string "X-Wing"). Pin the sequence.
        assert_eq!(XWING_LABEL, [0x5C, 0x2E, 0x2F, 0x2F, 0x5E, 0x5C]);
    }
}
