//! End-to-end roundtrip test using the Rust writer + Rust reader.
//!
//! This test is intra-Rust: it does not validate against the .NET
//! reference reader. That cross-impl validation lives in
//! `.github/workflows/differential-bidirectional.yml`. The point of
//! THIS test is fast-feedback during writer development: every PR
//! that touches the writer runs this in seconds and catches local
//! defects before the cross-impl gate runs.

use pqf_reader::{decrypt as reader_decrypt, parse as reader_parse, Identity};
use pqf_writer::{encrypt_to_bytes, encrypt_to_bytes_signed, RecipientPublicKey, SigningIdentity};

const PUBKEY_VERSION: u8 = 0x01;
const X25519_PK_LEN: usize = 32;

fn pubkey_from_identity(identity: &Identity) -> Vec<u8> {
    // Reader's Identity carries both halves as separate fields; reassemble
    // the canonical 1+32+1568 pubkey blob the writer takes.
    let mut out = Vec::with_capacity(1 + X25519_PK_LEN + identity.mlkem_pub.len());
    out.push(PUBKEY_VERSION);
    out.extend_from_slice(&identity.x25519_pub);
    out.extend_from_slice(&identity.mlkem_pub);
    out
}

/// Borrow id-a from the committed test-vector manifest. The values are
/// embedded inline so this test doesn't need to read files relative to
/// the workspace root, which makes `cargo test -p pqf-writer` self-
/// contained.
fn id_a() -> Identity {
    // Pulled verbatim from test-vectors/v1/manifest.json at HEAD.
    // If those bytes change, this test breaks and you regenerate from
    // the manifest. Keeping it inline is the simpler tradeoff.
    Identity::from_manifest(
        "id-a",
        include_str!("./fixtures/id-a.pub.b64").trim(),
        include_str!("./fixtures/id-a.x25519.b64").trim(),
        include_str!("./fixtures/id-a.mlkem.b64").trim(),
    )
    .expect("decode id-a")
}

#[test]
fn writer_then_reader_roundtrips_unsigned_small() {
    let id = id_a();
    let pubkey = RecipientPublicKey::from_canonical(&pubkey_from_identity(&id))
        .expect("pubkey form");

    let plaintext = b"hello, post-quantum world. this is the writer roundtrip test.".to_vec();
    let container = encrypt_to_bytes(&plaintext, &[pubkey], 4096).expect("encrypt");

    let parsed = reader_parse(&container).expect("reader accepts our container");
    let recovered = reader_decrypt(&parsed, &id).expect("reader decrypts our container");
    assert_eq!(recovered, plaintext);
}

#[test]
fn writer_then_reader_roundtrips_unsigned_multi_chunk() {
    let id = id_a();
    let pubkey = RecipientPublicKey::from_canonical(&pubkey_from_identity(&id))
        .expect("pubkey form");

    // Plaintext that spans several chunks at the minimum chunk size.
    let plaintext: Vec<u8> = (0..20_000).map(|i| (i as u32).wrapping_mul(31) as u8).collect();
    let container = encrypt_to_bytes(&plaintext, &[pubkey], 4096).expect("encrypt");

    let parsed = reader_parse(&container).expect("reader accepts our container");
    let recovered = reader_decrypt(&parsed, &id).expect("reader decrypts our container");
    assert_eq!(recovered, plaintext);
}

#[test]
fn writer_rejects_bad_chunk_size() {
    let id = id_a();
    let pubkey = RecipientPublicKey::from_canonical(&pubkey_from_identity(&id))
        .expect("pubkey form");

    // Not a power of two.
    let err = encrypt_to_bytes(b"x", &[pubkey], 5000).unwrap_err();
    assert!(format!("{err:?}").contains("InvalidChunkSize"));
}

#[test]
fn writer_then_reader_roundtrips_signed() {
    // Generate an ephemeral signing identity using the Rust crates directly.
    // (The reader doesn't need the signing private key to verify; only the
    // public counterparts need to be embedded in the header, which the
    // SigningIdentity carries through.)
    use ed25519_dalek::SigningKey as EdSk;
    use ml_dsa::{KeyGen, MlDsa87};
    use rand::rngs::OsRng;

    let id = id_a();
    let pubkey = RecipientPublicKey::from_canonical(&pubkey_from_identity(&id))
        .expect("pubkey form");

    let mut osrng = OsRng;
    let ed_sk = EdSk::generate(&mut osrng);
    let ed_pub = ed_sk.verifying_key();
    let ed_sk_bytes = ed_sk.to_bytes();
    let ed_pub_bytes = ed_pub.to_bytes();

    let kp = MlDsa87::key_gen(&mut osrng);
    let mldsa_sk_bytes = kp.signing_key().encode().to_vec();
    let mldsa_pub_bytes = kp.verifying_key().encode().to_vec();

    let signer = SigningIdentity::from_raw(ed_sk_bytes, ed_pub_bytes, mldsa_sk_bytes, mldsa_pub_bytes)
        .expect("signer construct");

    let plaintext = b"signed roundtrip test".to_vec();
    let container = encrypt_to_bytes_signed(&plaintext, &[pubkey], 4096, &signer).expect("encrypt-signed");

    let parsed = reader_parse(&container).expect("reader accepts our signed container");
    let recovered = reader_decrypt(&parsed, &id).expect("reader decrypts our signed container");
    assert_eq!(recovered, plaintext);
}
