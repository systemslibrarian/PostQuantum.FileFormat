//! pyo3 bindings for the PQF Rust reader.
//!
//! This is a deliberately thin wrapper: it exposes `parse_header` and
//! `decrypt` against bytes, plus an `Identity` Python class loaded from
//! manifest base64 strings. It does NOT expose the writer (the Rust
//! crate is reader-only by design) and does NOT generate keys.
//!
//! Build with:
//!     maturin develop --release
//! or
//!     maturin build --release
//!
//! Then in Python:
//!     import pqf
//!     header = pqf.parse_header(open("a.pqf","rb").read())
//!     identity = pqf.Identity.from_manifest("id-a", pub_b64, x25519_b64, mlkem_b64)
//!     plaintext = pqf.decrypt(open("a.pqf","rb").read(), identity)

use pqf_reader::{decrypt as rust_decrypt, parse as rust_parse, Identity as RustIdentity};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};

/// PQF version this binding targets. Surfaced as `pqf.__spec_version__`.
const SPEC_VERSION: &str = "v1 draft 0.3.1";

/// Recipient block, as a plain Python dict-like.
fn recipient_to_dict<'py>(
    py: Python<'py>,
    recipient: &pqf_reader::RecipientEntry,
) -> PyResult<&'py PyDict> {
    let d = PyDict::new(py);
    d.set_item("classical_epk", PyBytes::new(py, &recipient.classical_epk))?;
    d.set_item("pqc_ct", PyBytes::new(py, &recipient.pqc_ct))?;
    d.set_item("wrapped_dek", PyBytes::new(py, &recipient.wrapped_dek))?;
    d.set_item(
        "wrapped_dek_nonce",
        PyBytes::new(py, &recipient.wrapped_dek_nonce),
    )?;
    Ok(d)
}

/// Parse and structurally validate the header of a PQF file. Returns a
/// dict containing the algorithm identifiers, file_id, chunk size,
/// created timestamp, recipient list, and signer (or None).
///
/// Raises ValueError with a typed refusal reason on any malformed input.
#[pyfunction]
fn parse_header<'py>(py: Python<'py>, file_bytes: &[u8]) -> PyResult<&'py PyDict> {
    let parsed = rust_parse(file_bytes).map_err(map_err)?;
    let h = &parsed.header;
    let out = PyDict::new(py);

    let alg = PyDict::new(py);
    alg.set_item("aead", &h.alg.aead)?;
    alg.set_item("combiner", &h.alg.combiner)?;
    alg.set_item("kdf", &h.alg.kdf)?;
    alg.set_item("kem", &h.alg.kem)?;
    alg.set_item("sig", &h.alg.sig)?;
    out.set_item("alg", alg)?;

    out.set_item("chunk_size", h.chunk_size)?;
    out.set_item("created", &h.created)?;
    out.set_item("file_id", PyBytes::new(py, &h.file_id))?;

    let recipients = PyList::empty(py);
    for r in &h.recipients {
        recipients.append(recipient_to_dict(py, r)?)?;
    }
    out.set_item("recipients", recipients)?;

    if let Some(signer) = &h.signer {
        let s = PyDict::new(py);
        s.set_item("classical_pub", PyBytes::new(py, &signer.classical_pub))?;
        s.set_item("pqc_pub", PyBytes::new(py, &signer.pqc_pub))?;
        out.set_item("signer", s)?;
    } else {
        out.set_item("signer", py.None())?;
    }

    out.set_item("chunk_count", parsed.chunks.len())?;
    Ok(out)
}

/// Decrypt a PQF container under the given Identity. Returns the
/// plaintext as `bytes`. Authenticated Mode semantics: any failure
/// (header, signature, chunk tag, footer, post-trailer EOF) raises
/// ValueError before any plaintext is released.
#[pyfunction]
fn decrypt<'py>(py: Python<'py>, file_bytes: &[u8], identity: &Identity) -> PyResult<&'py PyBytes> {
    let parsed = rust_parse(file_bytes).map_err(map_err)?;
    let plaintext = rust_decrypt(&parsed, &identity.inner).map_err(map_err)?;
    Ok(PyBytes::new(py, &plaintext))
}

/// Identity (recipient long-term keys) for decryption. Loaded from the
/// base64-encoded fields in the test-vector manifest (or any compatible
/// source).
#[pyclass]
struct Identity {
    inner: RustIdentity,
}

#[pymethods]
impl Identity {
    /// Construct an Identity from the four base64 strings the manifest
    /// uses: id name, public-key blob, X25519 secret, ML-KEM-1024 secret.
    #[staticmethod]
    fn from_manifest(
        id: &str,
        public_key_b64: &str,
        x25519_sk_b64: &str,
        mlkem_sk_b64: &str,
    ) -> PyResult<Self> {
        let inner = RustIdentity::from_manifest(id, public_key_b64, x25519_sk_b64, mlkem_sk_b64)
            .map_err(map_err)?;
        Ok(Identity { inner })
    }

    #[getter]
    fn id(&self) -> &str {
        &self.inner.id
    }

    fn __repr__(&self) -> String {
        format!("<pqf.Identity id={:?}>", self.inner.id)
    }
}

fn map_err(e: pqf_reader::PqfError) -> PyErr {
    // A refusal is structurally a "bad input" — surface as ValueError so
    // Python callers can `except ValueError as e: ...` idiomatically.
    let _ = PyRuntimeError::new_err(""); // touch type so the import is not flagged
    PyValueError::new_err(format!("{:?}: {}", e.reason, e.message))
}

/// The Python module entry point.
#[pymodule]
fn pqf(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add("__spec_version__", SPEC_VERSION)?;
    m.add_class::<Identity>()?;
    m.add_function(wrap_pyfunction!(parse_header, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt, m)?)?;
    Ok(())
}
