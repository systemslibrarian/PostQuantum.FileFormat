//! Strict deterministic CBOR (RFC 8949 §4.2.2) decoder.
//!
//! This decoder implements only the CBOR subset PQF v1 actually uses:
//!
//! - Major type 0: unsigned integers
//! - Major type 2: byte strings
//! - Major type 3: text strings (UTF-8)
//! - Major type 4: arrays
//! - Major type 5: maps
//! - Major type 6: tags (only tag 0, RFC 3339 datetime, is accepted)
//! - Major type 7: simple values 20 (false), 21 (true), 22 (null)
//!
//! It refuses anything else: signed integers, floats, indefinite-length
//! items, simple values other than null/true/false, and any tag other than
//! tag 0. It enforces deterministic encoding rules:
//!
//! 1. Unsigned integers MUST use the shortest length form (no preferred-
//!    serialization slack).
//! 2. Map keys MUST be sorted by byte-wise lexicographic order of their
//!    encoded form, length-first, then lexicographic.
//! 3. Map keys MUST NOT repeat.
//!
//! Permissive parsing is non-conforming. Any deviation produces
//! `RefusalReason::NonDeterministicCborEncoding` (with `DuplicateCborKey`
//! used for the duplicate-key case to mirror the .NET reader).

use crate::error::{PqfError, RefusalReason, Result};

#[derive(Debug, Clone)]
pub enum CborValue {
    Uint(u64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<CborValue>),
    /// Map entries preserved in deterministic-CBOR sorted order.
    Map(Vec<(CborValue, CborValue)>),
    /// Tag 0 is the only tag PQF accepts (RFC 3339 datetime in a `tstr`).
    Tag0DateTime(String),
    Null,
    Bool(bool),
}

/// Parse `bytes` as a single deterministic-CBOR item and require that
/// nothing follows it. Returns `TrailingDataAfterExpectedEof` if there is
/// any extra byte beyond the parsed value.
pub fn parse_strict(bytes: &[u8]) -> Result<CborValue> {
    let mut cursor = Cursor::new(bytes);
    let value = decode_item(&mut cursor)?;
    if cursor.remaining() > 0 {
        return Err(PqfError::new(
            RefusalReason::TrailingDataAfterExpectedEof,
            format!("Trailing bytes after CBOR value: {} remaining", cursor.remaining()),
        ));
    }
    Ok(value)
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn read_u8(&mut self) -> Result<u8> {
        if self.pos >= self.data.len() {
            return Err(PqfError::new(
                RefusalReason::TruncationDetected,
                "CBOR truncated: expected initial byte",
            ));
        }
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }

    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(PqfError::new(
                RefusalReason::TruncationDetected,
                format!("CBOR truncated: needed {n} bytes, have {}", self.remaining()),
            ));
        }
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }
}

/// Decode the length / argument that follows a major-type byte, returning
/// the decoded value and rejecting non-shortest encodings.
fn decode_argument(cursor: &mut Cursor, info: u8) -> Result<u64> {
    match info {
        0..=23 => Ok(info as u64),
        24 => {
            let v = cursor.read_u8()? as u64;
            if v < 24 {
                return Err(PqfError::new(
                    RefusalReason::NonDeterministicCborEncoding,
                    "CBOR argument uses non-shortest 1-byte encoding",
                ));
            }
            Ok(v)
        }
        25 => {
            let bs = cursor.read_bytes(2)?;
            let v = u16::from_be_bytes([bs[0], bs[1]]) as u64;
            if v <= u8::MAX as u64 {
                return Err(PqfError::new(
                    RefusalReason::NonDeterministicCborEncoding,
                    "CBOR argument uses non-shortest 2-byte encoding",
                ));
            }
            Ok(v)
        }
        26 => {
            let bs = cursor.read_bytes(4)?;
            let v = u32::from_be_bytes([bs[0], bs[1], bs[2], bs[3]]) as u64;
            if v <= u16::MAX as u64 {
                return Err(PqfError::new(
                    RefusalReason::NonDeterministicCborEncoding,
                    "CBOR argument uses non-shortest 4-byte encoding",
                ));
            }
            Ok(v)
        }
        27 => {
            let bs = cursor.read_bytes(8)?;
            let v = u64::from_be_bytes([
                bs[0], bs[1], bs[2], bs[3], bs[4], bs[5], bs[6], bs[7],
            ]);
            if v <= u32::MAX as u64 {
                return Err(PqfError::new(
                    RefusalReason::NonDeterministicCborEncoding,
                    "CBOR argument uses non-shortest 8-byte encoding",
                ));
            }
            Ok(v)
        }
        28..=30 => Err(PqfError::new(
            RefusalReason::NonDeterministicCborEncoding,
            "CBOR reserved additional-info value (28-30)",
        )),
        31 => Err(PqfError::new(
            RefusalReason::NonDeterministicCborEncoding,
            "Indefinite-length CBOR items are non-deterministic",
        )),
        _ => unreachable!("info is 5 bits"),
    }
}

fn decode_item(cursor: &mut Cursor) -> Result<CborValue> {
    let initial = cursor.read_u8()?;
    let major = initial >> 5;
    let info = initial & 0x1f;

    match major {
        0 => {
            let v = decode_argument(cursor, info)?;
            Ok(CborValue::Uint(v))
        }
        1 => Err(PqfError::new(
            RefusalReason::NonDeterministicCborEncoding,
            "Negative integers are not used in PQF v1 headers",
        )),
        2 => {
            let len = decode_argument(cursor, info)? as usize;
            let bytes = cursor.read_bytes(len)?.to_vec();
            Ok(CborValue::Bytes(bytes))
        }
        3 => {
            let len = decode_argument(cursor, info)? as usize;
            let bytes = cursor.read_bytes(len)?.to_vec();
            let s = String::from_utf8(bytes).map_err(|_| {
                PqfError::new(
                    RefusalReason::NonDeterministicCborEncoding,
                    "CBOR text string is not valid UTF-8",
                )
            })?;
            Ok(CborValue::Text(s))
        }
        4 => {
            let len = decode_argument(cursor, info)? as usize;
            let mut items = Vec::with_capacity(len);
            for _ in 0..len {
                items.push(decode_item(cursor)?);
            }
            Ok(CborValue::Array(items))
        }
        5 => {
            let len = decode_argument(cursor, info)? as usize;
            let mut entries: Vec<(CborValue, CborValue)> = Vec::with_capacity(len);
            let mut last_key_bytes: Option<Vec<u8>> = None;
            for _ in 0..len {
                // Capture the key's raw encoding so we can verify deterministic ordering.
                let key_start = cursor.pos;
                let key = decode_item(cursor)?;
                let key_bytes = cursor.data[key_start..cursor.pos].to_vec();

                if let Some(prev) = &last_key_bytes {
                    match compare_deterministic(prev, &key_bytes) {
                        std::cmp::Ordering::Less => { /* ok */ }
                        std::cmp::Ordering::Equal => {
                            return Err(PqfError::new(
                                RefusalReason::DuplicateCborKey,
                                "CBOR map contains duplicate key",
                            ));
                        }
                        std::cmp::Ordering::Greater => {
                            return Err(PqfError::new(
                                RefusalReason::NonDeterministicCborEncoding,
                                "CBOR map keys are not in deterministic (length-first) order",
                            ));
                        }
                    }
                }
                last_key_bytes = Some(key_bytes);

                let value = decode_item(cursor)?;
                entries.push((key, value));
            }
            Ok(CborValue::Map(entries))
        }
        6 => {
            let tag = decode_argument(cursor, info)?;
            if tag != 0 {
                return Err(PqfError::new(
                    RefusalReason::NonDeterministicCborEncoding,
                    format!("Unsupported CBOR tag {tag}; PQF v1 only permits tag 0"),
                ));
            }
            let inner = decode_item(cursor)?;
            match inner {
                CborValue::Text(s) => Ok(CborValue::Tag0DateTime(s)),
                _ => Err(PqfError::new(
                    RefusalReason::CreatedTimestampInvalid,
                    "CBOR tag 0 must wrap a text string",
                )),
            }
        }
        7 => match info {
            20 => Ok(CborValue::Bool(false)),
            21 => Ok(CborValue::Bool(true)),
            22 => Ok(CborValue::Null),
            // simple-value extension byte (24) and floats (25-27) are
            // intentionally rejected.
            _ => Err(PqfError::new(
                RefusalReason::NonDeterministicCborEncoding,
                format!("CBOR major-type-7 value with info {info} is not permitted in PQF v1"),
            )),
        },
        _ => unreachable!("major type is 3 bits"),
    }
}

/// Length-first deterministic byte comparison: shorter encodings sort
/// before longer encodings; equal-length encodings sort lexicographically.
fn compare_deterministic(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    a.len()
        .cmp(&b.len())
        .then_with(|| a.cmp(b))
}
