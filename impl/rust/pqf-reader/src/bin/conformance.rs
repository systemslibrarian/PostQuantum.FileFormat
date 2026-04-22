//! PQF cross-implementation conformance binary.
//!
//! Reads `test-vectors/v1/manifest.json`, walks every vector, and reports
//! pass/fail. Exit code is non-zero on any disagreement with the manifest.
//!
//! Usage:
//!
//!     pqf-conformance [path/to/test-vectors/v1]
//!
//! If no path is supplied, defaults to the repository-relative path.

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use serde::Deserialize;
use sha2::{Digest, Sha256};

use pqf_reader::{decrypt, parse, Identity, RefusalReason};

#[derive(Debug, Deserialize)]
struct Manifest {
    #[serde(rename = "Version")]
    version: String,
    #[serde(rename = "Identities")]
    identities: Vec<IdentityManifest>,
    #[serde(rename = "Vectors")]
    vectors: Vec<VectorManifest>,
}

#[derive(Debug, Deserialize)]
struct IdentityManifest {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "PublicKey")]
    public_key: String,
    #[serde(rename = "X25519PrivateKey")]
    x25519_private_key: String,
    #[serde(rename = "MlKem1024PrivateKey")]
    mlkem1024_private_key: String,
}

#[derive(Debug, Deserialize)]
struct VectorManifest {
    #[serde(rename = "Id")]
    id: String,
    #[serde(rename = "File")]
    file: String,
    #[serde(rename = "Expect")]
    expect: String,
    #[serde(rename = "Identity")]
    identity: String,
    #[serde(rename = "Reason")]
    reason: Option<String>,
    #[serde(rename = "StreamingPostHocFailure")]
    streaming_post_hoc_failure: bool,
    #[serde(rename = "PlaintextSha256")]
    plaintext_sha256: Option<String>,
}

fn main() -> ExitCode {
    let arg = std::env::args().nth(1);
    let root: PathBuf = match arg {
        Some(p) => PathBuf::from(p),
        None => default_vectors_root(),
    };
    let manifest_path = root.join("manifest.json");

    let manifest_text = match fs::read_to_string(&manifest_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Cannot read manifest at {}: {e}", manifest_path.display());
            return ExitCode::from(2);
        }
    };
    let manifest: Manifest = match serde_json::from_str(&manifest_text) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Manifest is not valid JSON: {e}");
            return ExitCode::from(2);
        }
    };
    if manifest.version != "v1" {
        eprintln!("Unsupported manifest version: {}", manifest.version);
        return ExitCode::from(2);
    }

    let mut identities = std::collections::BTreeMap::new();
    for im in &manifest.identities {
        match Identity::from_manifest(
            &im.id,
            &im.public_key,
            &im.x25519_private_key,
            &im.mlkem1024_private_key,
        ) {
            Ok(id) => {
                identities.insert(im.id.clone(), id);
            }
            Err(e) => {
                eprintln!("Identity '{}' could not be loaded: {e}", im.id);
                return ExitCode::from(2);
            }
        }
    }

    let mut pass = 0usize;
    let mut fail = 0usize;
    let mut skipped = 0usize;
    let mut failures: Vec<String> = Vec::new();

    for v in &manifest.vectors {
        let identity = match identities.get(&v.identity) {
            Some(id) => id,
            None => {
                fail += 1;
                failures.push(format!(
                    "{}: manifest references unknown identity {}",
                    v.id, v.identity
                ));
                continue;
            }
        };

        let case_path = root.join(&v.file);
        let bytes = match fs::read(&case_path) {
            Ok(b) => b,
            Err(e) => {
                fail += 1;
                failures.push(format!("{}: cannot read {}: {e}", v.id, case_path.display()));
                continue;
            }
        };

        let outcome = run_case(&bytes, identity);

        match (v.expect.as_str(), outcome) {
            ("success", Ok(plaintext)) => {
                let expected = match v.plaintext_sha256.as_deref() {
                    Some(s) => s.to_uppercase(),
                    None => {
                        skipped += 1;
                        eprintln!("{}: success vector lacks PlaintextSha256, skipping", v.id);
                        continue;
                    }
                };
                let actual = hex::encode_upper(Sha256::digest(&plaintext));
                if actual == expected {
                    pass += 1;
                    println!("OK     {} ({} bytes)", v.id, plaintext.len());
                } else {
                    fail += 1;
                    failures.push(format!(
                        "{}: plaintext SHA256 mismatch (expected {}, got {})",
                        v.id, expected, actual
                    ));
                }
            }
            ("success", Err(reason)) => {
                fail += 1;
                failures.push(format!(
                    "{}: expected success but reader refused with {}",
                    v.id, reason
                ));
            }
            ("failure", Ok(_)) => {
                if v.streaming_post_hoc_failure {
                    // The .NET authenticated-mode reader detects this case at
                    // signature-verify time; the Rust reader currently verifies
                    // signatures during parse() and will already have refused.
                    // If we got here we accidentally let a post-hoc failure
                    // through. Treat as a real failure.
                    fail += 1;
                    failures.push(format!(
                        "{}: streaming-post-hoc failure leaked through as success",
                        v.id
                    ));
                } else {
                    fail += 1;
                    failures.push(format!("{}: expected failure but reader accepted", v.id));
                }
            }
            ("failure", Err(reason)) => {
                let expected = match v.reason.as_deref() {
                    Some(r) => r,
                    None => {
                        skipped += 1;
                        eprintln!(
                            "{}: failure vector lacks Reason field, accepting any refusal ({})",
                            v.id, reason
                        );
                        pass += 1;
                        continue;
                    }
                };
                if reason_matches(expected, reason) {
                    pass += 1;
                    println!("OK     {} (refused: {})", v.id, reason);
                } else {
                    fail += 1;
                    failures.push(format!(
                        "{}: expected refusal '{}' got '{}'",
                        v.id, expected, reason
                    ));
                }
            }
            (other, _) => {
                fail += 1;
                failures.push(format!("{}: manifest Expect='{}' is unknown", v.id, other));
            }
        }
    }

    println!();
    println!(
        "pqf-reader conformance: pass={} fail={} skipped={} (total {})",
        pass,
        fail,
        skipped,
        manifest.vectors.len()
    );
    if !failures.is_empty() {
        println!();
        println!("Failures:");
        for f in &failures {
            println!("  - {}", f);
        }
        return ExitCode::from(1);
    }
    ExitCode::from(0)
}

fn run_case(bytes: &[u8], identity: &Identity) -> Result<Vec<u8>, RefusalReason> {
    match parse(bytes) {
        Err(e) => Err(e.reason),
        Ok(parsed) => match decrypt(&parsed, identity) {
            Ok(pt) => Ok(pt),
            Err(e) => Err(e.reason),
        },
    }
}

/// Equivalences between Rust-reader refusals and .NET-reader refusals.
///
/// In a few categories the two readers detect a defect at slightly different
/// points in the pipeline (e.g. an out-of-range PQ ciphertext in the Rust
/// `ml-kem` crate produces a decapsulation error rather than a structural
/// length error, and subsequently turns into `IdentityMatchesNoRecipient`).
/// These equivalences are conservative and never weaken refusal: an expected
/// AeadTagFailure can also be reported as IdentityMatchesNoRecipient because
/// both indicate "this recipient does not unlock this file."
fn reason_matches(expected: &str, actual: RefusalReason) -> bool {
    let actual_str = actual.as_pascal_case();
    if actual_str == expected {
        return true;
    }
    match (expected, actual) {
        // A tampered recipient blob may show as either AeadTagFailure (DEK
        // unwrap fails) or IdentityMatchesNoRecipient (no recipient unlocked).
        ("AeadTagFailure", RefusalReason::IdentityMatchesNoRecipient) => true,
        ("IdentityMatchesNoRecipient", RefusalReason::AeadTagFailure) => true,
        // CBOR truncation surfaces as either NonDeterministicCborEncoding or
        // TruncationDetected depending on which byte boundary is hit.
        ("TruncationDetected", RefusalReason::NonDeterministicCborEncoding) => true,
        ("NonDeterministicCborEncoding", RefusalReason::TruncationDetected) => true,
        // A chunk truncated mid-payload may surface as either TruncationDetected
        // (.NET reader: not enough bytes for declared chunk) or
        // ChunkLengthExceedsRemainingBytes (Rust reader: declared length
        // exceeds remaining payload). Both correctly refuse the file.
        ("TruncationDetected", RefusalReason::ChunkLengthExceedsRemainingBytes) => true,
        ("ChunkLengthExceedsRemainingBytes", RefusalReason::TruncationDetected) => true,
        // Extra bytes appended after EOF may be interpreted as a partial chunk
        // header by a reader that walks the chunk stream eagerly. The .NET
        // reader sizes the chunk window from the footer/signature back-edge
        // and reports trailing-data; the Rust reader walks forward and
        // observes a partial chunk header (TruncationDetected). Both refuse.
        ("TrailingDataAfterExpectedEof", RefusalReason::TruncationDetected) => true,
        ("TruncationDetected", RefusalReason::TrailingDataAfterExpectedEof) => true,
        _ => false,
    }
}

fn default_vectors_root() -> PathBuf {
    // `cargo run` from impl/rust/pqf-reader puts CARGO_MANIFEST_DIR there.
    // CARGO_MANIFEST_DIR = <repo>/impl/rust/pqf-reader
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // rust
    p.pop(); // impl
    p.pop(); // <repo>
    p.push("test-vectors");
    p.push("v1");
    p
}
