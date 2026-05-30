//! Identity loading from the PQF test-vector manifest.
//!
//! The manifest stores each identity as base64-encoded:
//!   - `PublicKey`             : 1217-byte canonical PqfPublicKey
//!     (`0x01 || x25519_pub(32) || mlkem768_pub(1184)`).
//!   - `X25519PrivateKey`      : raw 32-byte X25519 scalar.
//!   - `MlKem768PrivateKey`    : 2400-byte FIPS 203 expanded decapsulation
//!     key (BouncyCastle `MLKemPrivateKeyParameters.GetEncoded()` form,
//!     which matches the canonical FIPS 203 dk serialization).
//!
//! v0.4.0: switched from ML-KEM-1024 (1568 byte pubkey, 3168 byte dk) to
//! ML-KEM-768 (1184 byte pubkey, 2400 byte dk) as part of the X-Wing
//! migration.

use base64::{engine::general_purpose::STANDARD, Engine as _};

use crate::error::{PqfError, RefusalReason, Result};

const PUBKEY_VERSION: u8 = 0x01;
const PUBKEY_X25519_LEN: usize = 32;
/// ML-KEM-768 public-key length per FIPS 203.
const PUBKEY_MLKEM_LEN: usize = 1184;
const PUBKEY_TOTAL_LEN: usize = 1 + PUBKEY_X25519_LEN + PUBKEY_MLKEM_LEN;

const X25519_PRIV_LEN: usize = 32;
/// FIPS 203 expanded decapsulation key length for ML-KEM-768.
pub const MLKEM768_DK_LEN: usize = 2400;

#[derive(Clone)]
pub struct Identity {
    pub id: String,
    pub x25519_pub: [u8; PUBKEY_X25519_LEN],
    pub mlkem_pub: Vec<u8>,
    pub x25519_sk: [u8; X25519_PRIV_LEN],
    pub mlkem_sk: Vec<u8>,
}

impl Identity {
    pub fn from_manifest(
        id: &str,
        public_key_b64: &str,
        x25519_sk_b64: &str,
        mlkem_sk_b64: &str,
    ) -> Result<Self> {
        let pub_bytes = STANDARD.decode(public_key_b64).map_err(|e| {
            PqfError::new(
                RefusalReason::BinaryFieldLengthMismatch,
                format!("identity {id}: public key not valid base64: {e}"),
            )
        })?;
        if pub_bytes.len() != PUBKEY_TOTAL_LEN {
            return Err(PqfError::new(
                RefusalReason::BinaryFieldLengthMismatch,
                format!(
                    "identity {id}: public key length {} != {}",
                    pub_bytes.len(),
                    PUBKEY_TOTAL_LEN
                ),
            ));
        }
        if pub_bytes[0] != PUBKEY_VERSION {
            return Err(PqfError::new(
                RefusalReason::BinaryFieldLengthMismatch,
                format!(
                    "identity {id}: public key version byte 0x{:02x} != 0x01",
                    pub_bytes[0]
                ),
            ));
        }
        let mut x25519_pub = [0u8; PUBKEY_X25519_LEN];
        x25519_pub.copy_from_slice(&pub_bytes[1..1 + PUBKEY_X25519_LEN]);
        let mlkem_pub = pub_bytes[1 + PUBKEY_X25519_LEN..].to_vec();

        let x25519_sk_bytes = STANDARD.decode(x25519_sk_b64).map_err(|e| {
            PqfError::new(
                RefusalReason::BinaryFieldLengthMismatch,
                format!("identity {id}: X25519 private key not valid base64: {e}"),
            )
        })?;
        if x25519_sk_bytes.len() != X25519_PRIV_LEN {
            return Err(PqfError::new(
                RefusalReason::BinaryFieldLengthMismatch,
                format!(
                    "identity {id}: X25519 private key length {} != {}",
                    x25519_sk_bytes.len(),
                    X25519_PRIV_LEN
                ),
            ));
        }
        let mut x25519_sk = [0u8; X25519_PRIV_LEN];
        x25519_sk.copy_from_slice(&x25519_sk_bytes);

        let mlkem_sk = STANDARD.decode(mlkem_sk_b64).map_err(|e| {
            PqfError::new(
                RefusalReason::BinaryFieldLengthMismatch,
                format!("identity {id}: ML-KEM-768 private key not valid base64: {e}"),
            )
        })?;
        if mlkem_sk.len() != MLKEM768_DK_LEN {
            return Err(PqfError::new(
                RefusalReason::BinaryFieldLengthMismatch,
                format!(
                    "identity {id}: ML-KEM-768 private key length {} != {}",
                    mlkem_sk.len(),
                    MLKEM768_DK_LEN
                ),
            ));
        }

        Ok(Self {
            id: id.to_string(),
            x25519_pub,
            mlkem_pub,
            x25519_sk,
            mlkem_sk,
        })
    }
}
