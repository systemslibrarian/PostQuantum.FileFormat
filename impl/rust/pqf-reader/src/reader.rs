//! PQF v1 file walker, recipient trial, hybrid signature verifier, and
//! chunk decryptor.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use ed25519_dalek::{Signature as EdSig, Verifier, VerifyingKey as EdVerifyingKey};
use hkdf::Hkdf;

use ml_kem::array::Array;
use ml_kem::kem::Decapsulate;
use ml_kem::ml_kem_768::{Ciphertext as MlKem768Ct, DecapsulationKey as MlKem768Dk};
use ml_kem::ExpandedKeyEncoding;
use sha2::{Digest, Sha256};
use sha3::Sha3_256;
use x25519_dalek::{PublicKey as XPub, StaticSecret as XSec};

use crate::cbor;
use crate::error::{PqfError, RefusalReason, Result};
use crate::header::{self, Header, RecipientEntry, SignerEntry};
use crate::identity::Identity;

// On-disk constants (see PQF spec §3, §4, §5).
const MAGIC: [u8; 4] = *b"PQF1";
const VERSION: u16 = 0x0001;
const MAX_HEADER_LEN: u32 = 1_048_576;
const HYBRID_SIG_LEN: usize = 4691;
const ED25519_SIG_LEN: usize = 64;
// Footer: 'PQFE' (4) + chunk_count u64 BE (8) + plaintext_bytes u64 BE (8) = 20.
const FOOTER_LEN: usize = 20;
const FOOTER_MAGIC: [u8; 4] = *b"PQFE";

// X-Wing combiner label per draft-connolly-cfrg-xwing-kem: the literal
// 6-byte ASCII art "\.//^\". This is NOT the ASCII string "X-Wing".
// Any deviation silently fails interop with conforming X-Wing impls.
const XWING_LABEL: [u8; 6] = [0x5C, 0x2E, 0x2F, 0x2F, 0x5E, 0x5C];

// Per-chunk HKDF expand label (unchanged from v0.3.x; this HKDF is for
// chunk key derivation from the DEK and has nothing to do with the KEM
// combiner).
const CHUNK_INFO_PREFIX: &[u8] = b"PQF1-chunk-v1";

// Signature-message domain-separation prefixes (spec §6.2). The header
// signature and file signature use the same hybrid key but disjoint
// pre-images by construction. Must byte-match HybridSigner in .NET.
const HEADER_SIG_DOMAIN: &[u8] = b"PQF1-header-sig-v1";
const FILE_SIG_DOMAIN: &[u8] = b"PQF1-file-sig-v1";

/// Result of parsing and validating a PQF file's structure.
pub struct ParsedFile {
    pub header: Header,
    pub header_signature: Option<[u8; HYBRID_SIG_LEN]>,
    pub file_signature: Option<[u8; HYBRID_SIG_LEN]>,
    pub header_bytes: Vec<u8>,
    pub footer_bytes: [u8; FOOTER_LEN],
    pub chunks: Vec<ChunkRecord>,
    pub chunks_sha256: [u8; 32],
    pub total_plaintext_bytes: u64,
    pub total_chunk_count: u64,
}

#[derive(Clone)]
pub struct ChunkRecord {
    pub index: u64,
    pub is_final: bool,
    pub ciphertext: Vec<u8>, // includes 16-byte tag
}

/// Parse and structurally validate a PQF file (no decryption).
///
/// Performs every check the spec mandates that doesn't require a
/// recipient identity:
///
///   * magic, version, header length bound
///   * deterministic CBOR enforcement
///   * header schema enforcement
///   * footer presence and consistency
///   * chunk-header structural validity
///   * trailing-data check
///
/// If the header declares a signer, verifies BOTH the header signature AND
/// the file signature (over `file_id || sha256(chunks) || footer`). If
/// either signature fails, returns `SignatureVerificationFailure`.
pub fn parse(file_bytes: &[u8]) -> Result<ParsedFile> {
    if file_bytes.len() < 4 || file_bytes[..4] != MAGIC {
        return Err(PqfError::new(
            RefusalReason::MagicMismatch,
            "File magic is not 'PQF1'",
        ));
    }
    if file_bytes.len() < 6 {
        return Err(PqfError::new(
            RefusalReason::TruncationDetected,
            "Truncated before version field",
        ));
    }
    let version = u16::from_be_bytes([file_bytes[4], file_bytes[5]]);
    if version != VERSION {
        return Err(PqfError::new(
            RefusalReason::VersionMismatch,
            format!("Version 0x{version:04x} != 0x{VERSION:04x}"),
        ));
    }
    if file_bytes.len() < 10 {
        return Err(PqfError::new(
            RefusalReason::TruncationDetected,
            "Truncated before header length",
        ));
    }
    let header_len = u32::from_be_bytes([
        file_bytes[6],
        file_bytes[7],
        file_bytes[8],
        file_bytes[9],
    ]);
    if header_len == 0 || header_len > MAX_HEADER_LEN {
        return Err(PqfError::new(
            RefusalReason::HeaderLengthExceedsLimit,
            format!("Header length {header_len} not in (0, {MAX_HEADER_LEN}]"),
        ));
    }
    let header_end = 10usize.checked_add(header_len as usize).ok_or_else(|| {
        PqfError::new(
            RefusalReason::HeaderLengthExceedsLimit,
            "Header length overflow",
        )
    })?;
    if file_bytes.len() < header_end {
        return Err(PqfError::new(
            RefusalReason::TruncationDetected,
            "Truncated inside header",
        ));
    }

    let header_bytes = &file_bytes[10..header_end];
    let header_value = cbor::parse_strict(header_bytes)?;
    let header = header::parse(header_value)?;

    // Optional header signature (4691 bytes) follows header iff signer is present.
    let mut cursor = header_end;
    let header_signature = if header.signer.is_some() {
        if file_bytes.len() < cursor + HYBRID_SIG_LEN {
            return Err(PqfError::new(
                RefusalReason::TruncationDetected,
                "Signed file truncated before header signature",
            ));
        }
        let mut sig = [0u8; HYBRID_SIG_LEN];
        sig.copy_from_slice(&file_bytes[cursor..cursor + HYBRID_SIG_LEN]);
        cursor += HYBRID_SIG_LEN;
        Some(sig)
    } else {
        None
    };

    let trailing = FOOTER_LEN + if header.signer.is_some() { HYBRID_SIG_LEN } else { 0 };
    if file_bytes.len() < cursor + trailing {
        return Err(PqfError::new(
            RefusalReason::TruncationDetected,
            "Truncated before footer/signature",
        ));
    }
    let payload_end = file_bytes.len() - trailing;

    // Walk chunk frames: each is 4-byte length BE + 1-byte flags + ciphertext.
    let mut chunks: Vec<ChunkRecord> = Vec::new();
    let mut chunks_hasher = Sha256::new();
    let mut p = cursor;
    let mut saw_final = false;
    while p < payload_end {
        if payload_end - p < 5 {
            return Err(PqfError::new(
                RefusalReason::TruncationDetected,
                "Chunk header truncated",
            ));
        }
        if saw_final {
            return Err(PqfError::new(
                RefusalReason::TrailingDataAfterExpectedEof,
                "Chunk found after final-chunk flag",
            ));
        }
        let chunk_len = u32::from_be_bytes([
            file_bytes[p],
            file_bytes[p + 1],
            file_bytes[p + 2],
            file_bytes[p + 3],
        ]) as usize;
        let flags = file_bytes[p + 4];
        if flags & 0xfe != 0 {
            return Err(PqfError::new(
                RefusalReason::ReservedChunkFlagBitsSet,
                format!("Reserved chunk flag bits set: 0x{flags:02x}"),
            ));
        }
        let is_final = flags & 0x01 != 0;
        if chunk_len < 16 {
            return Err(PqfError::new(
                RefusalReason::ChunkLengthExceedsRemainingBytes,
                "Chunk length below AEAD tag size",
            ));
        }
        if payload_end - p - 5 < chunk_len {
            return Err(PqfError::new(
                RefusalReason::ChunkLengthExceedsRemainingBytes,
                "Chunk length exceeds remaining payload bytes",
            ));
        }
        // Hash chunk-header + ciphertext (matches .NET writer's pre-image).
        chunks_hasher.update(&file_bytes[p..p + 5]);
        chunks_hasher.update(&file_bytes[p + 5..p + 5 + chunk_len]);

        chunks.push(ChunkRecord {
            index: chunks.len() as u64,
            is_final,
            ciphertext: file_bytes[p + 5..p + 5 + chunk_len].to_vec(),
        });
        if is_final {
            saw_final = true;
        }
        p += 5 + chunk_len;
    }
    if p != payload_end {
        return Err(PqfError::new(
            RefusalReason::TrailingDataAfterExpectedEof,
            "Trailing data between chunks and footer",
        ));
    }

    // Footer
    let mut footer_bytes = [0u8; FOOTER_LEN];
    footer_bytes.copy_from_slice(&file_bytes[payload_end..payload_end + FOOTER_LEN]);
    if footer_bytes[..4] != FOOTER_MAGIC {
        return Err(PqfError::new(
            RefusalReason::FooterMagicInvalid,
            "Footer magic is not 'PQFE'",
        ));
    }
    let chunk_count = u64::from_be_bytes(footer_bytes[4..12].try_into().unwrap());
    let plaintext_bytes = u64::from_be_bytes(footer_bytes[12..20].try_into().unwrap());
    if chunk_count != chunks.len() as u64 {
        return Err(PqfError::new(
            RefusalReason::FooterChunkCountMismatch,
            format!(
                "Footer chunk_count {chunk_count} != observed {}",
                chunks.len()
            ),
        ));
    }
    let observed_plaintext: u64 = chunks
        .iter()
        .map(|c| (c.ciphertext.len() - 16) as u64)
        .sum();
    if plaintext_bytes != observed_plaintext {
        return Err(PqfError::new(
            RefusalReason::FooterPlaintextBytesMismatch,
            format!(
                "Footer plaintext_bytes {plaintext_bytes} != observed {observed_plaintext}"
            ),
        ));
    }
    let chunks_sha256: [u8; 32] = chunks_hasher.finalize().into();

    // File signature (only when signer present).
    let file_signature = if header.signer.is_some() {
        let sig_off = payload_end + FOOTER_LEN;
        if file_bytes.len() != sig_off + HYBRID_SIG_LEN {
            return Err(PqfError::new(
                RefusalReason::TrailingDataAfterExpectedEof,
                format!(
                    "Unexpected file length: signed file should end at {} bytes, got {}",
                    sig_off + HYBRID_SIG_LEN,
                    file_bytes.len()
                ),
            ));
        }
        let mut sig = [0u8; HYBRID_SIG_LEN];
        sig.copy_from_slice(&file_bytes[sig_off..sig_off + HYBRID_SIG_LEN]);
        Some(sig)
    } else {
        if file_bytes.len() != payload_end + FOOTER_LEN {
            return Err(PqfError::new(
                RefusalReason::TrailingDataAfterExpectedEof,
                format!(
                    "Unsigned file should end at {} bytes, got {}",
                    payload_end + FOOTER_LEN,
                    file_bytes.len()
                ),
            ));
        }
        None
    };

    // Verify hybrid signatures eagerly (parse-time refusal).
    if let Some(signer) = &header.signer {
        let mut header_sig_msg = Vec::with_capacity(HEADER_SIG_DOMAIN.len() + header_bytes.len());
        header_sig_msg.extend_from_slice(HEADER_SIG_DOMAIN);
        header_sig_msg.extend_from_slice(header_bytes);
        let hsig = header_signature.as_ref().expect("signer => header sig");
        if !verify_hybrid_signature(signer, &header_sig_msg, hsig) {
            return Err(PqfError::new(
                RefusalReason::SignatureVerificationFailure,
                "Header hybrid signature verification failed",
            ));
        }

        let mut signed_msg = Vec::with_capacity(FILE_SIG_DOMAIN.len() + 16 + 32 + FOOTER_LEN);
        signed_msg.extend_from_slice(FILE_SIG_DOMAIN);
        signed_msg.extend_from_slice(&header.file_id);
        signed_msg.extend_from_slice(&chunks_sha256);
        signed_msg.extend_from_slice(&footer_bytes);
        let fsig = file_signature.as_ref().expect("signer => file sig");
        if !verify_hybrid_signature(signer, &signed_msg, fsig) {
            return Err(PqfError::new(
                RefusalReason::SignatureVerificationFailure,
                "File hybrid signature verification failed",
            ));
        }
    }

    Ok(ParsedFile {
        header,
        header_signature,
        file_signature,
        header_bytes: header_bytes.to_vec(),
        footer_bytes,
        chunks,
        chunks_sha256,
        total_plaintext_bytes: plaintext_bytes,
        total_chunk_count: chunk_count,
    })
}

/// Decrypt a parsed PQF file using the given identity. Returns the full
/// plaintext on success.
///
/// The recipient trial loop iterates over all recipients and attempts to
/// derive a KEK and unwrap the DEK from each. If no recipient yields a
/// valid DEK, the file is refused with `IdentityMatchesNoRecipient`.
pub fn decrypt(parsed: &ParsedFile, identity: &Identity) -> Result<Vec<u8>> {
    // Build identity material once.
    let x_sec = XSec::from(identity.x25519_sk);
    let mlkem_dk = decode_mlkem_dk(&identity.mlkem_sk)?;

    // Constant-time recipient trial (spec §6.5): iterate ALL recipients
    // even after a match. ML-KEM implicit rejection means a malformed
    // ciphertext returns a pseudorandom secret, so we never short-circuit
    // on "wrong recipient" — the AEAD tag is the sole signal.
    let mut found_dek: Option<[u8; 32]> = None;
    for (idx, r) in parsed.recipients_iter().enumerate() {
        // X25519 ECDH. ss_X (X-Wing) = X25519(sk_X, ct_X).
        let epk = XPub::from(r.classical_epk);
        let ss_classical = x_sec.diffie_hellman(&epk);

        // ML-KEM-768 decapsulation. ss_M (X-Wing) = ML-KEM-Decap(dk_M, ct_M).
        let ct_arr = MlKem768Ct::try_from(r.pqc_ct.as_slice()).map_err(|_| {
            PqfError::new(
                RefusalReason::BinaryFieldLengthMismatch,
                "ML-KEM-768 ciphertext length mismatch",
            )
        })?;
        let ss_pqc = match mlkem_dk.decapsulate(&ct_arr) {
            Ok(ss) => ss,
            Err(_) => continue,
        };

        // X-Wing combiner: KEK = SHA3-256(ss_M || ss_X || ct_X || pk_X || label)
        // (draft-connolly-cfrg-xwing-kem). pk_X is the recipient's own
        // X25519 public key, recomputed from the static secret so we
        // never trust a value carried in the header for this purpose.
        // Per draft-connolly-cfrg-xwing-kem the label is APPENDED:
        //   SHA3-256(ss_M || ss_X || ct_X || pk_X || XWingLabel)
        // An earlier version of this code prepended the label; the
        // X-Wing draft KAT in pqf-writer/tests/xwing_draft_kat.rs caught
        // the discrepancy on 2026-05-30.
        let pk_x: [u8; 32] = XPub::from(&x_sec).to_bytes();
        let mut sha3 = <Sha3_256 as sha3::Digest>::new();
        sha3.update(ss_pqc.as_slice());          // ss_M (32)
        sha3.update(ss_classical.as_bytes());    // ss_X (32)
        sha3.update(&r.classical_epk);           // ct_X (32)
        sha3.update(&pk_x);                      // pk_X (32)
        sha3.update(XWING_LABEL);                // 6 bytes "\.//^\"
        let kek_arr = sha3.finalize();
        let mut kek = [0u8; 32];
        kek.copy_from_slice(&kek_arr);

        // Unwrap DEK with AES-256-GCM. AAD binds file instance AND
        // recipient slot (the bindings X-Wing's combiner has no salt
        // slot for); nonce comes from the wrapped_dek_nonce field.
        let mut aad = [0u8; 20];
        aad[..16].copy_from_slice(&parsed.header.file_id);
        aad[16..].copy_from_slice(&(idx as u32).to_be_bytes());

        let cipher = Aes256Gcm::new_from_slice(&kek).expect("kek is 32 bytes");
        let nonce = Nonce::from_slice(&r.wrapped_dek_nonce);
        let pt = cipher.decrypt(
            nonce,
            Payload {
                msg: &r.wrapped_dek,
                aad: &aad,
            },
        );
        // Zero the KEK as soon as we are done with it. The DEK (when
        // successfully unwrapped) is held only in `found_dek`.
        for b in kek.iter_mut() { *b = 0; }
        match pt {
            Ok(dek_bytes) if dek_bytes.len() == 32 => {
                if found_dek.is_none() {
                    let mut dek = [0u8; 32];
                    dek.copy_from_slice(&dek_bytes);
                    found_dek = Some(dek);
                }
                // Continue trialling remaining recipients for constant-time
                // hygiene (spec §6.5).
            }
            _ => continue,
        }
    }

    let dek = found_dek.ok_or_else(|| {
        PqfError::new(
            RefusalReason::IdentityMatchesNoRecipient,
            "Identity did not unwrap any recipient DEK",
        )
    })?;

    // Decrypt every chunk in order.
    let mut plaintext = Vec::with_capacity(parsed.total_plaintext_bytes as usize);
    for chunk in &parsed.chunks {
        // Per-chunk key = HKDF-Expand(dek, info = "PQF1-chunk-v1" || idx_be64).
        let mut info = Vec::with_capacity(CHUNK_INFO_PREFIX.len() + 8);
        info.extend_from_slice(CHUNK_INFO_PREFIX);
        info.extend_from_slice(&chunk.index.to_be_bytes());
        let hk = Hkdf::<Sha256>::from_prk(&dek).map_err(|_| {
            PqfError::new(
                RefusalReason::AeadTagFailure,
                "HKDF init failed for chunk key",
            )
        })?;
        let mut chunk_key = [0u8; 32];
        hk.expand(&info, &mut chunk_key).map_err(|_| {
            PqfError::new(
                RefusalReason::AeadTagFailure,
                "HKDF-Expand failed for chunk key",
            )
        })?;

        // AAD = file_id || idx_be64 || is_final byte.
        let mut aad = Vec::with_capacity(16 + 8 + 1);
        aad.extend_from_slice(&parsed.header.file_id);
        aad.extend_from_slice(&chunk.index.to_be_bytes());
        aad.push(if chunk.is_final { 1 } else { 0 });

        let cipher = Aes256Gcm::new_from_slice(&chunk_key).expect("chunk key 32 bytes");
        let nonce = Nonce::from_slice(&[0u8; 12]);
        let pt = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &chunk.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| {
                PqfError::new(
                    RefusalReason::AeadTagFailure,
                    format!("AEAD tag verification failed for chunk {}", chunk.index),
                )
            })?;
        plaintext.extend_from_slice(&pt);
    }

    if plaintext.len() as u64 != parsed.total_plaintext_bytes {
        return Err(PqfError::new(
            RefusalReason::FooterPlaintextBytesMismatch,
            "Decrypted plaintext length mismatch with footer",
        ));
    }
    Ok(plaintext)
}

impl ParsedFile {
    fn recipients_iter(&self) -> std::slice::Iter<'_, RecipientEntry> {
        self.header.recipients.iter()
    }
}

// ---------- hybrid signature verification ----------

fn verify_hybrid_signature(
    signer: &SignerEntry,
    message: &[u8],
    signature: &[u8; HYBRID_SIG_LEN],
) -> bool {
    let ed_ok = verify_ed25519(&signer.ed25519_pub, message, &signature[..ED25519_SIG_LEN]);
    let dsa_ok = verify_mldsa87(&signer.mldsa87_pub, message, &signature[ED25519_SIG_LEN..]);
    // Bitwise & to keep both branches always evaluated (matches L-3 hardening
    // in the .NET reference reader).
    ed_ok & dsa_ok
}

fn verify_ed25519(pub_key: &[u8; 32], message: &[u8], sig: &[u8]) -> bool {
    let pk = match EdVerifyingKey::from_bytes(pub_key) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let s_arr: [u8; 64] = match sig.try_into() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let s = EdSig::from_bytes(&s_arr);
    pk.verify(message, &s).is_ok()
}

fn verify_mldsa87(pub_key: &[u8], message: &[u8], sig: &[u8]) -> bool {
    use ml_dsa::{MlDsa87, VerifyingKey};
    let pk_arr = match <[u8; 2592]>::try_from(pub_key) {
        Ok(a) => a,
        Err(_) => return false,
    };
    let pk_encoded =
        ml_dsa::EncodedVerifyingKey::<MlDsa87>::try_from(pk_arr.as_slice()).ok();
    let Some(pk_encoded) = pk_encoded else {
        return false;
    };
    let vk = VerifyingKey::<MlDsa87>::decode(&pk_encoded);
    let sig_arr = match <[u8; 4627]>::try_from(sig) {
        Ok(a) => a,
        Err(_) => return false,
    };
    let sig_encoded = match ml_dsa::EncodedSignature::<MlDsa87>::try_from(sig_arr.as_slice()) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let Some(parsed) = ml_dsa::Signature::<MlDsa87>::decode(&sig_encoded) else {
        return false;
    };
    vk.verify_with_context(message, &[], &parsed)
}

fn decode_mlkem_dk(bytes: &[u8]) -> Result<MlKem768Dk> {
    let encoded: &Array<u8, <MlKem768Dk as ExpandedKeyEncoding>::EncodedSize> =
        bytes.try_into().map_err(|_| {
            PqfError::new(
                RefusalReason::BinaryFieldLengthMismatch,
                format!(
                    "ML-KEM-768 decapsulation key length {} != expected",
                    bytes.len()
                ),
            )
        })?;
    MlKem768Dk::from_expanded_bytes(encoded).map_err(|_| {
        PqfError::new(
            RefusalReason::BinaryFieldLengthMismatch,
            "ML-KEM-768 expanded key validation failed".to_string(),
        )
    })
}
