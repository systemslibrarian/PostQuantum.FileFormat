//! Deterministic CBOR encoding for the PQF v1 header.
//!
//! Implements RFC 8949 §4.2.2 deterministic encoding rules:
//!   - Smallest possible integer encoding (definite length only).
//!   - Map keys sorted in byte-lexicographic order of their CBOR encoding.
//!   - Definite-length strings and arrays.
//!   - UTF-8 strings; no indefinite-length items.
//!
//! This module is intentionally encoder-only and standalone — it does
//! not touch any cryptographic state. That makes it unit-testable
//! against committed test vector bytes.

use crate::error::{WriterError, WriterResult};
use crate::{RecipientMaterial, SignerMaterial};

const HEADER_MAX_LEN: usize = 1_048_576;

const MLKEM1024_CT_LEN: usize = 1568;
const WRAPPED_DEK_LEN: usize = 48;
const MLDSA87_PK_LEN: usize = 2592;

pub fn build_header(
    file_id: [u8; 16],
    chunk_size: u32,
    created_rfc3339: &str,
    recipients: &[RecipientMaterial],
    signer: Option<&SignerMaterial>,
) -> WriterResult<Vec<u8>> {
    if !(chunk_size >= 4096 && chunk_size <= 16_777_216 && chunk_size.is_power_of_two()) {
        return Err(WriterError::InvalidChunkSize(chunk_size));
    }
    for r in recipients {
        if r.pqc_ct.len() != MLKEM1024_CT_LEN {
            return Err(WriterError::RecipientFieldLength {
                field: "pqc_ct",
                got: r.pqc_ct.len(),
                want: MLKEM1024_CT_LEN,
            });
        }
        if r.wrapped_dek.len() != WRAPPED_DEK_LEN {
            return Err(WriterError::RecipientFieldLength {
                field: "wrapped_dek",
                got: r.wrapped_dek.len(),
                want: WRAPPED_DEK_LEN,
            });
        }
    }
    if let Some(s) = signer {
        if s.pqc_pub.len() != MLDSA87_PK_LEN {
            return Err(WriterError::RecipientFieldLength {
                field: "signer.pqc_pub",
                got: s.pqc_pub.len(),
                want: MLDSA87_PK_LEN,
            });
        }
    }

    let mut buf = Vec::with_capacity(2048);

    // Top-level map size: alg, chunk_size, created, file_id, recipients,
    // plus optional signer.
    let map_size = 5 + signer.map_or(0, |_| 1);
    write_type_and_len(&mut buf, 5, map_size as u64);

    // Keys must be sorted in byte-lexicographic order of their CBOR
    // encoding (RFC 8949 §4.2.1). For short text strings the CBOR
    // encoding starts with the type+length byte then the bytes, so the
    // simple-text ordering by length then lexicographic over bytes is
    // what we want. The five required keys, sorted:
    //   alg, chunk_size, created, file_id, recipients
    // The optional "signer" key sorts AFTER "recipients" because their
    // length differs (8 vs 10) and the CBOR-encoded length prefix
    // dominates. Since both fit in immediate-length encoding, the
    // shorter-first rule applies: alg(3), created(7), file_id(7),
    // chunk_size(10), recipients(10), signer(6).
    // Wait — RFC 8949 §4.2.1 (bytewise lex over the encoded key):
    //   "alg"        -> 63 61 6c 67          (4 bytes total)
    //   "signer"     -> 66 73 69 67 6e 65 72 (7 bytes)
    //   "chunk_size" -> 6a 63 68 75 6e 6b 5f 73 69 7a 65 (11)
    //   "created"    -> 67 63 72 65 61 74 65 64 (8)
    //   "file_id"    -> 67 66 69 6c 65 5f 69 64 (8)
    //   "recipients" -> 6a 72 65 63 69 70 69 65 6e 74 73 (11)
    //   Shorter encoded byte string sorts first per §4.2.1.
    // Final order: alg, signer, created, file_id, chunk_size, recipients.

    write_text(&mut buf, "alg");
    write_alg_map(&mut buf);

    if let Some(s) = signer {
        write_text(&mut buf, "signer");
        write_signer_map(&mut buf, s);
    }
    let _ = write_signer_map_dispatch; // silence unused-fn lint on the stub helper

    write_text(&mut buf, "created");
    // CBOR tag 0 (RFC 3339 text per RFC 8949 §3.4.1).
    write_type_and_len(&mut buf, 6, 0);
    write_text(&mut buf, created_rfc3339);

    write_text(&mut buf, "file_id");
    write_bstr(&mut buf, &file_id);

    write_text(&mut buf, "chunk_size");
    write_type_and_len(&mut buf, 0, chunk_size as u64);

    write_text(&mut buf, "recipients");
    write_type_and_len(&mut buf, 4, recipients.len() as u64);
    for r in recipients {
        write_recipient(&mut buf, r);
    }

    if buf.len() > HEADER_MAX_LEN {
        return Err(WriterError::HeaderTooLarge(buf.len()));
    }
    Ok(buf)
}

fn write_alg_map(buf: &mut Vec<u8>) {
    // alg keys sorted as for the top-level map. Bytewise on encoded keys:
    //   "aead"     -> 64 61 65 61 64
    //   "combiner" -> 68 63 6f 6d 62 69 6e 65 72
    //   "kdf"      -> 63 6b 64 66
    //   "kem"      -> 63 6b 65 6d
    //   "sig"      -> 63 73 69 67
    // Shorter encodings first; for equal-length keys, bytewise lex.
    // Resulting order: kdf, kem, sig, aead, combiner.
    write_type_and_len(buf, 5, 5);
    write_text(buf, "kdf");
    write_text(buf, "hkdf-sha256");
    write_text(buf, "kem");
    write_text(buf, "x25519+ml-kem-1024");
    write_text(buf, "sig");
    write_text(buf, "ed25519+ml-dsa-87");
    write_text(buf, "aead");
    write_text(buf, "aes-256-gcm-chunked");
    write_text(buf, "combiner");
    write_text(buf, "pqf1-concat-extract-v1");
}

fn write_signer_map(buf: &mut Vec<u8>, s: &SignerMaterial) {
    // Keys: classical_pub, pqc_pub. Both equal-encoded-length so
    // bytewise lex on the text decides: classical_pub < pqc_pub.
    write_type_and_len(buf, 5, 2);
    write_text(buf, "classical_pub");
    write_bstr(buf, &s.classical_pub);
    write_text(buf, "pqc_pub");
    write_bstr(buf, &s.pqc_pub);
}

#[doc(hidden)]
fn write_signer_map_dispatch(buf: &mut Vec<u8>, s: &SignerMaterial) {
    write_signer_map(buf, s);
}

fn write_recipient(buf: &mut Vec<u8>, r: &RecipientMaterial) {
    // Four required fields. Sort by encoded-key bytewise lex:
    //   "classical_epk"     -> 6d ...    (14 bytes)
    //   "pqc_ct"            -> 66 ...    (7 bytes)
    //   "wrapped_dek"       -> 6b ...    (12)
    //   "wrapped_dek_nonce" -> 71 ...    (18)
    // Shorter first: pqc_ct, wrapped_dek, classical_epk, wrapped_dek_nonce.
    write_type_and_len(buf, 5, 4);
    write_text(buf, "pqc_ct");
    write_bstr(buf, &r.pqc_ct);
    write_text(buf, "wrapped_dek");
    write_bstr(buf, &r.wrapped_dek);
    write_text(buf, "classical_epk");
    write_bstr(buf, &r.classical_epk);
    write_text(buf, "wrapped_dek_nonce");
    write_bstr(buf, &r.wrapped_dek_nonce);
}

/// CBOR major-type + length, using the smallest possible encoding
/// (RFC 8949 §4.2.2).
fn write_type_and_len(buf: &mut Vec<u8>, major: u8, value: u64) {
    let prefix = major << 5;
    if value < 24 {
        buf.push(prefix | (value as u8));
    } else if value < 0x100 {
        buf.push(prefix | 24);
        buf.push(value as u8);
    } else if value < 0x10000 {
        buf.push(prefix | 25);
        buf.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value < 0x1_0000_0000 {
        buf.push(prefix | 26);
        buf.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        buf.push(prefix | 27);
        buf.extend_from_slice(&value.to_be_bytes());
    }
}

fn write_text(buf: &mut Vec<u8>, s: &str) {
    write_type_and_len(buf, 3, s.len() as u64);
    buf.extend_from_slice(s.as_bytes());
}

fn write_bstr(buf: &mut Vec<u8>, b: &[u8]) {
    write_type_and_len(buf, 2, b.len() as u64);
    buf.extend_from_slice(b);
}
