//! PQF v1 header schema enforcement.
//!
//! After deterministic CBOR parsing, this module re-walks the parsed value
//! and enforces the strict PQF v1 schema: required fields are present, their
//! types and binary lengths are correct, no unknown fields appear at any
//! level, and the algorithm-identifier strings match exactly.

use std::collections::HashSet;

use crate::cbor::CborValue;
use crate::error::{PqfError, RefusalReason, Result};

/// Spec §3.1, §4: required header field set.
const REQUIRED_TOP_FIELDS: &[&str] = &["alg", "chunk_size", "created", "file_id", "recipients"];
const KNOWN_TOP_FIELDS: &[&str] = &[
    "alg",
    "chunk_size",
    "created",
    "file_id",
    "recipients",
    "signer",
];

const ALG_REQUIRED: &[(&str, &str)] = &[
    ("aead", "aes-256-gcm-chunked"),
    ("combiner", "pqf1-concat-extract-v1"),
    ("kdf", "hkdf-sha256"),
    ("kem", "x25519+ml-kem-1024"),
    ("sig", "ed25519+ml-dsa-87"),
];

const RECIPIENT_FIELDS: &[&str] = &["classical_epk", "pqc_ct", "wrapped_dek", "wrapped_dek_nonce"];
const SIGNER_FIELDS: &[&str] = &["classical_pub", "pqc_pub"];

// Spec §4.4 fixed binary lengths
const X25519_EPK_LEN: usize = 32;
const MLKEM1024_CT_LEN: usize = 1568;
const WRAPPED_DEK_LEN: usize = 48;
const WRAPPED_DEK_NONCE_LEN: usize = 12;
const ED25519_PUB_LEN: usize = 32;
const MLDSA87_PUB_LEN: usize = 2592;
const FILE_ID_LEN: usize = 16;

const MIN_CHUNK_SIZE: u64 = 4096;
const MAX_CHUNK_SIZE: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Header {
    pub file_id: [u8; FILE_ID_LEN],
    pub chunk_size: u64,
    pub created: String,
    pub recipients: Vec<RecipientEntry>,
    pub signer: Option<SignerEntry>,
}

#[derive(Debug, Clone)]
pub struct RecipientEntry {
    pub classical_epk: [u8; X25519_EPK_LEN],
    pub pqc_ct: Vec<u8>, // 1568 bytes
    pub wrapped_dek: [u8; WRAPPED_DEK_LEN],
    pub wrapped_dek_nonce: [u8; WRAPPED_DEK_NONCE_LEN],
}

#[derive(Debug, Clone)]
pub struct SignerEntry {
    pub ed25519_pub: [u8; ED25519_PUB_LEN],
    pub mldsa87_pub: Vec<u8>, // 2592 bytes
}

pub fn parse(value: CborValue) -> Result<Header> {
    let entries = expect_map(value, "header")?;
    let map = collect_text_map(entries, "header")?;

    enforce_known_keys(&map, KNOWN_TOP_FIELDS, "header")?;
    for required in REQUIRED_TOP_FIELDS {
        if !map.contains_key(*required) {
            return Err(PqfError::new(
                RefusalReason::MissingRequiredField,
                format!("Header missing required field '{required}'"),
            ));
        }
    }

    parse_alg(&map["alg"])?;

    let chunk_size = match &map["chunk_size"] {
        CborValue::Uint(v) => *v,
        _ => {
            return Err(PqfError::new(
                RefusalReason::ChunkSizeInvalid,
                "chunk_size must be a CBOR unsigned integer",
            ))
        }
    };
    if chunk_size < MIN_CHUNK_SIZE
        || chunk_size > MAX_CHUNK_SIZE
        || (chunk_size & (chunk_size - 1)) != 0
    {
        return Err(PqfError::new(
            RefusalReason::ChunkSizeInvalid,
            format!(
                "chunk_size {chunk_size} not a power-of-two in [{MIN_CHUNK_SIZE},{MAX_CHUNK_SIZE}]"
            ),
        ));
    }

    let created = match &map["created"] {
        CborValue::Tag0DateTime(s) => s.clone(),
        _ => {
            return Err(PqfError::new(
                RefusalReason::CreatedTimestampInvalid,
                "created must be a CBOR tag-0 RFC 3339 datetime",
            ))
        }
    };
    if !looks_like_rfc3339_zulu(&created) {
        return Err(PqfError::new(
            RefusalReason::CreatedTimestampInvalid,
            format!("created '{created}' is not RFC 3339 Zulu form"),
        ));
    }

    let file_id_bytes = expect_bytes(&map["file_id"], "file_id")?;
    if file_id_bytes.len() != FILE_ID_LEN {
        return Err(PqfError::new(
            RefusalReason::BinaryFieldLengthMismatch,
            format!("file_id length {} != {FILE_ID_LEN}", file_id_bytes.len()),
        ));
    }
    let mut file_id = [0u8; FILE_ID_LEN];
    file_id.copy_from_slice(file_id_bytes);

    let recipient_items = expect_array(&map["recipients"], "recipients")?;
    if recipient_items.is_empty() {
        return Err(PqfError::new(
            RefusalReason::RecipientsEmpty,
            "recipients array is empty",
        ));
    }
    let mut recipients = Vec::with_capacity(recipient_items.len());
    for (idx, item) in recipient_items.iter().enumerate() {
        recipients.push(parse_recipient(item, idx)?);
    }

    let signer = if let Some(signer_value) = map.get("signer") {
        Some(parse_signer(signer_value)?)
    } else {
        None
    };

    Ok(Header {
        file_id,
        chunk_size,
        created,
        recipients,
        signer,
    })
}

fn parse_alg(value: &CborValue) -> Result<()> {
    let entries = match value {
        CborValue::Map(e) => e,
        _ => {
            return Err(PqfError::new(
                RefusalReason::AlgorithmIdentifierMismatch,
                "alg must be a CBOR map",
            ))
        }
    };
    let map = collect_text_map_ref(entries, "alg")?;
    let known: Vec<&str> = ALG_REQUIRED.iter().map(|(k, _)| *k).collect();
    enforce_known_keys(&map, &known, "alg")?;
    for (k, expected) in ALG_REQUIRED {
        let v = map.get(*k).ok_or_else(|| {
            PqfError::new(
                RefusalReason::AlgorithmIdentifierMismatch,
                format!("alg missing key '{k}'"),
            )
        })?;
        match v {
            CborValue::Text(s) if s == expected => {}
            _ => {
                return Err(PqfError::new(
                    RefusalReason::AlgorithmIdentifierMismatch,
                    format!("alg.{k} != '{expected}'"),
                ))
            }
        }
    }
    Ok(())
}

fn parse_recipient(value: &CborValue, idx: usize) -> Result<RecipientEntry> {
    let entries = match value {
        CborValue::Map(e) => e,
        _ => {
            return Err(PqfError::new(
                RefusalReason::MissingRequiredField,
                format!("recipients[{idx}] is not a CBOR map"),
            ))
        }
    };
    let map = collect_text_map_ref(entries, &format!("recipients[{idx}]"))?;
    enforce_known_keys(&map, RECIPIENT_FIELDS, &format!("recipients[{idx}]"))?;
    for required in RECIPIENT_FIELDS {
        if !map.contains_key(*required) {
            return Err(PqfError::new(
                RefusalReason::MissingRequiredField,
                format!("recipients[{idx}] missing '{required}'"),
            ));
        }
    }

    let classical_epk_bytes = expect_bytes(map["classical_epk"], "classical_epk")?;
    if classical_epk_bytes.len() != X25519_EPK_LEN {
        return Err(PqfError::new(
            RefusalReason::BinaryFieldLengthMismatch,
            format!(
                "recipients[{idx}].classical_epk length {} != {X25519_EPK_LEN}",
                classical_epk_bytes.len()
            ),
        ));
    }
    let mut classical_epk = [0u8; X25519_EPK_LEN];
    classical_epk.copy_from_slice(classical_epk_bytes);

    let pqc_ct = expect_bytes(map["pqc_ct"], "pqc_ct")?;
    if pqc_ct.len() != MLKEM1024_CT_LEN {
        return Err(PqfError::new(
            RefusalReason::BinaryFieldLengthMismatch,
            format!(
                "recipients[{idx}].pqc_ct length {} != {MLKEM1024_CT_LEN}",
                pqc_ct.len()
            ),
        ));
    }

    let wrapped_dek_bytes = expect_bytes(map["wrapped_dek"], "wrapped_dek")?;
    if wrapped_dek_bytes.len() != WRAPPED_DEK_LEN {
        return Err(PqfError::new(
            RefusalReason::BinaryFieldLengthMismatch,
            format!(
                "recipients[{idx}].wrapped_dek length {} != {WRAPPED_DEK_LEN}",
                wrapped_dek_bytes.len()
            ),
        ));
    }
    let mut wrapped_dek = [0u8; WRAPPED_DEK_LEN];
    wrapped_dek.copy_from_slice(wrapped_dek_bytes);

    let wrapped_dek_nonce_bytes = expect_bytes(map["wrapped_dek_nonce"], "wrapped_dek_nonce")?;
    if wrapped_dek_nonce_bytes.len() != WRAPPED_DEK_NONCE_LEN {
        return Err(PqfError::new(
            RefusalReason::BinaryFieldLengthMismatch,
            format!(
                "recipients[{idx}].wrapped_dek_nonce length {} != {WRAPPED_DEK_NONCE_LEN}",
                wrapped_dek_nonce_bytes.len()
            ),
        ));
    }
    let mut wrapped_dek_nonce = [0u8; WRAPPED_DEK_NONCE_LEN];
    wrapped_dek_nonce.copy_from_slice(wrapped_dek_nonce_bytes);

    Ok(RecipientEntry {
        classical_epk,
        pqc_ct: pqc_ct.to_vec(),
        wrapped_dek,
        wrapped_dek_nonce,
    })
}

fn parse_signer(value: &CborValue) -> Result<SignerEntry> {
    let entries = match value {
        CborValue::Map(e) => e,
        _ => {
            return Err(PqfError::new(
                RefusalReason::MissingRequiredField,
                "signer is not a CBOR map",
            ))
        }
    };
    let map = collect_text_map_ref(entries, "signer")?;
    enforce_known_keys(&map, SIGNER_FIELDS, "signer")?;
    for required in SIGNER_FIELDS {
        if !map.contains_key(*required) {
            return Err(PqfError::new(
                RefusalReason::MissingRequiredField,
                format!("signer missing '{required}'"),
            ));
        }
    }

    let classical_pub = expect_bytes(map["classical_pub"], "classical_pub")?;
    if classical_pub.len() != ED25519_PUB_LEN {
        return Err(PqfError::new(
            RefusalReason::BinaryFieldLengthMismatch,
            format!(
                "signer.classical_pub length {} != {ED25519_PUB_LEN}",
                classical_pub.len()
            ),
        ));
    }
    let mut ed25519_pub = [0u8; ED25519_PUB_LEN];
    ed25519_pub.copy_from_slice(classical_pub);

    let pqc_pub = expect_bytes(map["pqc_pub"], "pqc_pub")?;
    if pqc_pub.len() != MLDSA87_PUB_LEN {
        return Err(PqfError::new(
            RefusalReason::BinaryFieldLengthMismatch,
            format!(
                "signer.pqc_pub length {} != {MLDSA87_PUB_LEN}",
                pqc_pub.len()
            ),
        ));
    }

    Ok(SignerEntry {
        ed25519_pub,
        mldsa87_pub: pqc_pub.to_vec(),
    })
}

// ---------- helpers ----------

fn expect_map(value: CborValue, ctx: &str) -> Result<Vec<(CborValue, CborValue)>> {
    match value {
        CborValue::Map(m) => Ok(m),
        _ => Err(PqfError::new(
            RefusalReason::MissingRequiredField,
            format!("{ctx} is not a CBOR map"),
        )),
    }
}

fn expect_bytes<'a>(value: &'a CborValue, ctx: &str) -> Result<&'a [u8]> {
    match value {
        CborValue::Bytes(b) => Ok(b),
        _ => Err(PqfError::new(
            RefusalReason::BinaryFieldLengthMismatch,
            format!("{ctx} is not a CBOR byte string"),
        )),
    }
}

fn expect_array<'a>(value: &'a CborValue, ctx: &str) -> Result<&'a Vec<CborValue>> {
    match value {
        CborValue::Array(a) => Ok(a),
        _ => Err(PqfError::new(
            RefusalReason::MissingRequiredField,
            format!("{ctx} is not a CBOR array"),
        )),
    }
}

fn collect_text_map(
    entries: Vec<(CborValue, CborValue)>,
    ctx: &str,
) -> Result<std::collections::BTreeMap<String, CborValue>> {
    let mut out = std::collections::BTreeMap::new();
    for (k, v) in entries {
        let key = match k {
            CborValue::Text(s) => s,
            _ => {
                return Err(PqfError::new(
                    RefusalReason::NonDeterministicCborEncoding,
                    format!("{ctx} key is not a text string"),
                ))
            }
        };
        if out.insert(key.clone(), v).is_some() {
            return Err(PqfError::new(
                RefusalReason::DuplicateCborKey,
                format!("{ctx} key '{key}' duplicated"),
            ));
        }
    }
    Ok(out)
}

fn collect_text_map_ref<'a>(
    entries: &'a [(CborValue, CborValue)],
    ctx: &str,
) -> Result<std::collections::BTreeMap<&'a str, &'a CborValue>> {
    let mut out = std::collections::BTreeMap::new();
    for (k, v) in entries {
        let key = match k {
            CborValue::Text(s) => s.as_str(),
            _ => {
                return Err(PqfError::new(
                    RefusalReason::NonDeterministicCborEncoding,
                    format!("{ctx} key is not a text string"),
                ))
            }
        };
        if out.insert(key, v).is_some() {
            return Err(PqfError::new(
                RefusalReason::DuplicateCborKey,
                format!("{ctx} key '{key}' duplicated"),
            ));
        }
    }
    Ok(out)
}

fn enforce_known_keys<V>(
    map: &std::collections::BTreeMap<impl AsRef<str> + Ord, V>,
    known: &[&str],
    ctx: &str,
) -> Result<()> {
    let known_set: HashSet<&str> = known.iter().copied().collect();
    for k in map.keys() {
        if !known_set.contains(k.as_ref()) {
            return Err(PqfError::new(
                RefusalReason::UnknownHeaderField,
                format!("{ctx} contains unknown field '{}'", k.as_ref()),
            ));
        }
    }
    Ok(())
}

fn looks_like_rfc3339_zulu(s: &str) -> bool {
    // Match strict shape: YYYY-MM-DDTHH:MM:SSZ (20 chars, no fractional, no offset)
    if s.len() != 20 {
        return false;
    }
    let bytes = s.as_bytes();
    let digit = |i: usize| bytes[i].is_ascii_digit();
    digit(0) && digit(1) && digit(2) && digit(3)
        && bytes[4] == b'-'
        && digit(5) && digit(6)
        && bytes[7] == b'-'
        && digit(8) && digit(9)
        && bytes[10] == b'T'
        && digit(11) && digit(12)
        && bytes[13] == b':'
        && digit(14) && digit(15)
        && bytes[16] == b':'
        && digit(17) && digit(18)
        && bytes[19] == b'Z'
}
