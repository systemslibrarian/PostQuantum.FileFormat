//! WebAssembly bindings for the PQF Rust reader.
//!
//! Build with:
//!     wasm-pack build --release --target web
//!
//! The resulting `pkg/` directory contains a JS shim and the `.wasm`
//! payload. See demo/index.html for a minimal "paste a file, see the
//! header" page that loads them directly.

use pqf_reader::{decrypt as rust_decrypt, parse as rust_parse, Identity as RustIdentity};
use serde::Serialize;
use wasm_bindgen::prelude::*;

#[cfg(feature = "console_error_panic_hook")]
#[wasm_bindgen(start)]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

#[derive(Serialize)]
struct AlgJs {
    aead: String,
    combiner: String,
    kdf: String,
    kem: String,
    sig: String,
}

#[derive(Serialize)]
struct HeaderJs {
    alg: AlgJs,
    chunk_size: u32,
    created: String,
    file_id_hex: String,
    recipient_count: usize,
    signed: bool,
    chunk_count: usize,
}

/// Parse and structurally validate a PQF container header. Takes a
/// JS Uint8Array, returns a plain JS object describing the header
/// without revealing any byte-string material. Throws a JsError with
/// the typed refusal reason on malformed input.
#[wasm_bindgen]
pub fn parse_header(file_bytes: &[u8]) -> Result<JsValue, JsError> {
    let parsed = rust_parse(file_bytes).map_err(map_err)?;
    let h = &parsed.header;
    let js = HeaderJs {
        alg: AlgJs {
            aead: h.alg.aead.clone(),
            combiner: h.alg.combiner.clone(),
            kdf: h.alg.kdf.clone(),
            kem: h.alg.kem.clone(),
            sig: h.alg.sig.clone(),
        },
        chunk_size: h.chunk_size,
        created: h.created.clone(),
        file_id_hex: hex_lower(&h.file_id),
        recipient_count: h.recipients.len(),
        signed: h.signer.is_some(),
        chunk_count: parsed.chunks.len(),
    };
    serde_wasm_bindgen::to_value(&js).map_err(|e| JsError::new(&format!("serialize: {e}")))
}

/// Decrypt a PQF container under an identity loaded via Identity.fromManifest.
/// Returns the plaintext as a JS Uint8Array. Authenticated mode semantics.
#[wasm_bindgen]
pub fn decrypt(file_bytes: &[u8], identity: &Identity) -> Result<Vec<u8>, JsError> {
    let parsed = rust_parse(file_bytes).map_err(map_err)?;
    let plaintext = rust_decrypt(&parsed, &identity.inner).map_err(map_err)?;
    Ok(plaintext)
}

/// Recipient long-term identity for decryption.
#[wasm_bindgen]
pub struct Identity {
    inner: RustIdentity,
}

#[wasm_bindgen]
impl Identity {
    /// Construct an Identity from the four base64 strings the test-vector
    /// manifest uses: name, full public-key blob, X25519 secret, ML-KEM-1024
    /// secret.
    #[wasm_bindgen(js_name = "fromManifest")]
    pub fn from_manifest(
        id: &str,
        public_key_b64: &str,
        x25519_sk_b64: &str,
        mlkem_sk_b64: &str,
    ) -> Result<Identity, JsError> {
        let inner = RustIdentity::from_manifest(id, public_key_b64, x25519_sk_b64, mlkem_sk_b64)
            .map_err(map_err)?;
        Ok(Identity { inner })
    }

    #[wasm_bindgen(getter)]
    pub fn id(&self) -> String {
        self.inner.id.clone()
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}

fn map_err(e: pqf_reader::PqfError) -> JsError {
    JsError::new(&format!("{:?}: {}", e.reason, e.message))
}
