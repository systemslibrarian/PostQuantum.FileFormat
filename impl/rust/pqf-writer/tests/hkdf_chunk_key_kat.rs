// Pinned known-answer vectors for the per-chunk HKDF expansion (spec §5.2).
//
// Construction under test (mirrored in the .NET side at
// tests/PostQuantum.FileFormat.Tests/Crypto/HkdfCombinerKatTests.cs):
//
//   chunk_key = HKDF-Expand(SHA-256,
//                           PRK  = DEK,
//                           info = "PQF1-chunk-v1" || uint64BE(chunkIndex),
//                           L    = 32)
//
// Both impls must produce the same 32-byte chunk_key for every (DEK, chunkIndex)
// pair below. The vectors were generated and committed after dual independent
// computation: the .NET BCL HKDF.Expand(SHA256) and RFC 5869 §2.3 reduced
// single-block form (T(1) = HMAC-SHA256(PRK, info || 0x01)) agreed byte-exact.
// The Rust side asserts the same hex via the `hkdf` crate, an independent
// implementation again.

use hkdf::Hkdf;
use sha2::Sha256;

const CHUNK_INFO_PREFIX: &[u8] = b"PQF1-chunk-v1";

fn derive(dek_byte: u8, chunk_index: u64) -> [u8; 32] {
    let dek = [dek_byte; 32];
    let mut info = Vec::with_capacity(CHUNK_INFO_PREFIX.len() + 8);
    info.extend_from_slice(CHUNK_INFO_PREFIX);
    info.extend_from_slice(&chunk_index.to_be_bytes());

    let hk = Hkdf::<Sha256>::from_prk(&dek).expect("PRK length is 32, always valid for SHA-256");
    let mut chunk_key = [0u8; 32];
    hk.expand(&info, &mut chunk_key).expect("L = 32 ≤ 255 * 32");
    chunk_key
}

fn hex_upper(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02X}", b));
    }
    s
}

#[test]
fn dek44_idx0() {
    assert_eq!(
        hex_upper(&derive(0x44, 0)),
        "B9954575C12134A01D7DE7B2482230D68AFAF3D2222985B59C5F436FACF0286A"
    );
}

#[test]
fn dek44_idx1() {
    assert_eq!(
        hex_upper(&derive(0x44, 1)),
        "8AE81F7EA2402D261921E8415493C7159FB80E80F5C1A46C1D1513EF71022721"
    );
}

#[test]
fn dek44_idx_u64_max() {
    assert_eq!(
        hex_upper(&derive(0x44, u64::MAX)),
        "5F9E16CDCA00F4AF17FF5E990D1D274F12A095793FD48493A0C0A08840A86286"
    );
}

#[test]
fn dek00_idx0() {
    assert_eq!(
        hex_upper(&derive(0x00, 0)),
        "E0E05D84A15D93FF9B66A9325367871169B1EAC2ECD983A217BC0556CFF8D4A7"
    );
}

#[test]
fn dekff_idx0() {
    assert_eq!(
        hex_upper(&derive(0xFF, 0)),
        "765AB31275F7ACBF7AAF3500651B9528037427B55C8670C07F74503473D06DE8"
    );
}
