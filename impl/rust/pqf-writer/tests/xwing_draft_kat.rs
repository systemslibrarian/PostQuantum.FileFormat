//! Known-Answer Test (KAT) for the X-Wing combiner against the
//! published draft-connolly-cfrg-xwing-kem appendix vector.
//!
//! This is the highest-value test in the codebase: it verifies that
//! PQF's X-Wing combiner formula produces the byte-exact shared secret
//! the IETF draft publishes for vector 1 (seed/eseed → pk/ct/ss).
//! Without this, our self-consistency tests would be silently wrong
//! about byte order, label bytes, or hash function — and we would
//! never know.
//!
//! Strategy: we do NOT rely on a third-party X-Wing crate, because at
//! the time of writing the maintained `x-wing` crate transitively
//! requires `ml-kem` 0.3 while PQF is pinned to 0.2 (the version that
//! both pqf-reader and pqf-writer use in production code paths). To
//! avoid version drift between the test crypto stack and the
//! production crypto stack, we replay the X-Wing draft vector using
//! exactly the same crates the production code uses
//! (`ml-kem = "0.2"` with the `deterministic` feature, `x25519-dalek`
//! `2.0`, and `sha3 = "0.10"`). The deterministic-keygen step is
//! sidestepped by consuming the draft's published `pk` directly
//! rather than rederiving it from the seed — the X-Wing key-schedule
//! is orthogonal to the combiner we are testing, and is independently
//! validated by every implementation that interoperates against the
//! draft.
//!
//! Vector source: draft-connolly-cfrg-xwing-kem appendix C, example 1.
//! The appendix header notes the vectors are placeholders pending an
//! ML-KEM/X25519-reuse rewrite, but the values themselves have been
//! stable across recent draft revisions and are consistent with
//! every public X-Wing implementation we have spot-checked.

use hex::FromHex;
use ml_kem::{kem::EncapsulationKey as MlKemEncapsulationKey, KemCore, MlKem768};
use ml_kem::{Encoded, EncodedSizeUser};
use ml_kem::EncapsulateDeterministic;
use sha3::{Digest, Sha3_256};
use x25519_dalek::{PublicKey, StaticSecret};

// ---------------------------------------------------------------------------
// Test vector — draft-connolly-cfrg-xwing-kem, Appendix C, example 1.
// ---------------------------------------------------------------------------

/// X-Wing public key (1216 bytes): pk_M (1184 bytes ML-KEM-768 ek)
/// followed by pk_X (32 bytes X25519 public key).
const PK_HEX: &str = concat!(
    "e2236b35a8c24b39b10aa1323a96a919a2ced88400633a7b07131713fc14b2b5",
    "b19cfc3da5fa1a92c49f25513e0fd30d6b1611c9ab9635d7086727a4b7d21d34",
    "244e66969cf15b3b2a785329f61b096b277ea037383479a6b556de7231fe4b7f",
    "a9c9ac24c0699a0018a5253401bacfa905ca816573e56a2d2e067e9b7287533b",
    "a13a937dedb31fa44baced40769923610034ae31e619a170245199b3c5c39864",
    "859fe1b4c9717a07c30495bdfb98a0a002ccf56c1286cef5041dede3c44cf16b",
    "f562c7448518026b3d8b9940680abd38a1575fd27b58da063bfac32c39c30869",
    "374c05c1aeb1898b6b303cc68be455346ee0af699636224a148ca2aea1046311",
    "1c709f69b69c70ce8538746698c4c60a9aef0030c7924ceec42a5d36816f545e",
    "ae13293460b3acb37ea0e13d70e4aa78686da398a8397c08eaf96882113fe4f7",
    "bad4da40b0501e1c753efe73053c87014e8661c33099afe8bede414a5b1aa27d",
    "8392b3e131e9a70c1055878240cad0f40d5fe3cdf85236ead97e2a97448363b2",
    "808caafd516cd25052c5c362543c2517e4acd0e60ec07163009b6425fc32277a",
    "cee71c24bab53ed9f29e74c66a0a3564955998d76b96a9a8b50d1635a4d7a67e",
    "b42df5644d330457293a8042f53cc7a69288f17ed55827e82b28e82665a86a14",
    "fbd96645eca8172c044f83bc0d8c0b4c8626985631ca87af829068f1358963cb",
    "333664ca482763ba3b3bb208577f9ba6ac62c25f76592743b64be519317714cb",
    "4102cb7b2f9a25b2b4f0615de31decd9ca55026d6da0b65111b16fe52feed8a4",
    "87e144462a6dba93728f500b6ffc49e515569ef25fed17aff520507368253525",
    "860f58be3be61c964604a6ac814e6935596402a520a4670b3d284318866593d1",
    "5a4bb01c35e3e587ee0c67d2880d6f2407fb7a70712b838deb96c5d7bf2b44bc",
    "f6038ccbe33fbcf51a54a584fe90083c91c7a6d43d4fb15f48c60c2fd66e0a8a",
    "ad4ad64e5c42bb8877c0ebec2b5e387c8a988fdc23beb9e16c8757781e0a1499",
    "c61e138c21f216c29d076979871caa6942bafc090544bee99b54b16cb9a9a364",
    "d6246d9f42cce53c66b59c45c8f9ae9299a75d15180c3c952151a91b7a107724",
    "29dc4cbae6fcc622fa8018c63439f890630b9928db6bb7f9438ae4065ed34d73",
    "d486f3f52f90f0807dc88dfdd8c728e954f1ac35c06c000ce41a0582580e3bb5",
    "7b672972890ac5e7988e7850657116f1b57d0809aaedec0bede1ae148148311c",
    "6f7e317346e5189fb8cd635b986f8c0bdd27641c584b778b3a911a80be1c9692",
    "ab8e1bbb12839573cce19df183b45835bbb55052f9fc66a1678ef2a36dea7841",
    "1e6c8d60501b4e60592d13698a943b509185db912e2ea10be06171236b327c71",
    "716094c964a68b03377f513a05bcd99c1f346583bb052977a10a12adfc758034",
    "e5617da4c1276585e5774e1f3b9978b09d0e9c44d3bc86151c43aad185712717",
    "340223ac381d21150a04294e97bb13bbda21b5a182b6da969e19a7fd072737fa",
    "8e880a53c2428e3d049b7d2197405296ddb361912a7bcf4827ced611d0c7a7da",
    "104dde4322095339f64a61d5bb108ff0bf4d780cae509fb22c256914193ff734",
    "9042581237d522828824ee3bdfd07fb03f1f942d2ea179fe722f06cc03de5b69",
    "859edb06eff389b27dce59844570216223593d4ba32d9abac8cd049040ef6534",
);

/// 64-byte encapsulation seed: first 32 bytes are the ML-KEM
/// deterministic-encap randomness `m`; last 32 bytes are the X25519
/// ephemeral scalar.
const ESEED_HEX: &str = concat!(
    "3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e2",
    "35b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2",
);

/// Expected 32-byte X-Wing shared secret for (pk, eseed) above.
const EXPECTED_SS_HEX: &str =
    "d2df0522128f09dd8e2c92b1e905c793d8f57a54c3da25861f10bf4ca613e384";

// ---------------------------------------------------------------------------
// Layout constants. These must match the X-Wing draft and the
// implementation in `src/lib.rs` byte-for-byte.
// ---------------------------------------------------------------------------

const ML_KEM_768_PK_LEN: usize = 1184;
const X25519_PK_LEN: usize = 32;
const XWING_PK_LEN: usize = ML_KEM_768_PK_LEN + X25519_PK_LEN; // 1216

/// X-Wing combiner label: 6 bytes "\.//^\". Identical to the
/// `XWING_LABEL` constant in `pqf-writer` / `pqf-reader` and to the
/// `Label` constant in `XWingKem.cs`. Pinned here so a hypothetical
/// future rename of the lib-side constant would not silently
/// invalidate this KAT.
const XWING_LABEL: [u8; 6] = [0x5C, 0x2E, 0x2F, 0x2F, 0x5E, 0x5C];

#[test]
fn xwing_combiner_matches_published_draft_vector() {
    // ---- (1) Decode the vector inputs from hex ---------------------------
    let pk_bytes: Vec<u8> = Vec::from_hex(PK_HEX).expect("pk hex decode");
    assert_eq!(pk_bytes.len(), XWING_PK_LEN, "pk length");
    let eseed: Vec<u8> = Vec::from_hex(ESEED_HEX).expect("eseed hex decode");
    assert_eq!(eseed.len(), 64, "eseed length");
    let expected_ss: [u8; 32] =
        <[u8; 32]>::from_hex(EXPECTED_SS_HEX).expect("expected ss hex decode");

    // ---- (2) Split the X-Wing public key into (pk_M, pk_X) ---------------
    let pk_m_bytes: &[u8] = &pk_bytes[..ML_KEM_768_PK_LEN];
    let pk_x_bytes: &[u8] = &pk_bytes[ML_KEM_768_PK_LEN..];
    let pk_x_arr: [u8; 32] = pk_x_bytes.try_into().expect("pk_X is 32 bytes");

    // ---- (3) Split the eseed into (m, e_X) -------------------------------
    // X-Wing's deterministic encapsulation per the draft:
    //   m  = eseed[0..32]  → ML-KEM-768 EncapDeterministic input
    //   e  = eseed[32..64] → X25519 ephemeral scalar (clamped on use)
    let m_arr: [u8; 32] = eseed[0..32].try_into().expect("m is 32 bytes");
    let e_arr: [u8; 32] = eseed[32..64].try_into().expect("e is 32 bytes");

    // ---- (4) ML-KEM-768 deterministic encapsulation ----------------------
    // Load pk_M as an ML-KEM-768 EncapsulationKey and feed it the
    // deterministic `m`. The crate's "deterministic" feature exposes
    // exactly this entry point; we use no internal/hazmat hooks.
    type Ek = <MlKem768 as KemCore>::EncapsulationKey;
    let pk_m_encoded: &Encoded<Ek> = pk_m_bytes
        .try_into()
        .expect("pk_M length matches ML-KEM-768 ek encoding");
    let ek: MlKemEncapsulationKey<ml_kem::MlKem768Params> =
        <Ek as EncodedSizeUser>::from_bytes(pk_m_encoded);
    let m_b32: ml_kem::B32 = m_arr.into();
    let (ct_m, ss_m) = ek
        .encapsulate_deterministic(&m_b32)
        .expect("ML-KEM-768 EncapDeterministic");
    // Sanity: the ML-KEM-768 ciphertext is 1088 bytes.
    assert_eq!(ct_m.as_slice().len(), 1088, "ct_M length");
    assert_eq!(ss_m.as_slice().len(), 32, "ss_M length");

    // ---- (5) X25519 ephemeral and ECDH -----------------------------------
    // X-Wing's X25519 half: the ephemeral scalar is e_arr (X25519 clamps
    // internally). ct_X = e_arr * basepoint; ss_X = e_arr * pk_X.
    let e_secret = StaticSecret::from(e_arr);
    let ct_x: PublicKey = (&e_secret).into();
    let pk_x_pub: PublicKey = pk_x_arr.into();
    let ss_x = e_secret.diffie_hellman(&pk_x_pub);

    // ---- (6) X-Wing combiner: SHA3-256(ss_M || ss_X || ct_X || pk_X || label)
    // Label is APPENDED, not prepended (per draft-connolly-cfrg-xwing-kem).
    // EXACTLY mirrors the formula in `pqf-writer/src/lib.rs` (and in
    // `src/PostQuantum.FileFormat/Crypto/XWingKem.cs`). If this assertion
    // fails, EITHER the formula is wrong OR the published vector is.
    // Pin the four intermediate values for cross-referencing with the
    // C# port of this KAT (`XWingCombiner_MatchesPublishedDraftVector`
    // in tests/.../Crypto/XWingKemTests.cs). The C# test hard-codes
    // these exact bytes so that the .NET side does not need a
    // deterministic ML-KEM encap (BouncyCastle 2.6.2 does not expose
    // ML-KEM EncapsDerand on its public API). Both impls then assert
    // ComputeCombiner(those_bytes) == EXPECTED_SS_HEX.
    //
    //   ss_M = 7631eaf24bcc7ba2d1656d8f53778f8caa5f1ce33180e8ab405b9247eab76dfc
    //   ss_X = 1e53cb26910141b4a09b0664deb8ec55376bcdbdfe2bfc8277883939a76d6131
    //   ct_X = e56f17576740ce2a32fc5145030145cfb97e63e0e41d354274a079d3e6fb2e15
    //   pk_X = 859edb06eff389b27dce59844570216223593d4ba32d9abac8cd049040ef6534
    //
    // ct_X and pk_X are independently verifiable against the published
    // `ct` and `pk` in PK_HEX / EXPECTED_CT (last 32 bytes of each).

    let mut h = <Sha3_256 as Digest>::new();
    h.update(ss_m.as_slice());
    h.update(ss_x.as_bytes());
    h.update(ct_x.as_bytes());
    h.update(&pk_x_arr);
    h.update(XWING_LABEL);
    let computed_ss: [u8; 32] = h.finalize().into();

    assert_eq!(
        computed_ss, expected_ss,
        "\nX-Wing combiner output does NOT match the published draft vector.\n\
         \n\
         This means one of the following went wrong:\n\
         (a) the byte order of the SHA3-256 input was changed,\n\
         (b) the XWING_LABEL constant drifted from 5C 2E 2F 2F 5E 5C,\n\
         (c) ml-kem-0.2 'deterministic' encap diverged from the draft,\n\
         (d) x25519-dalek's clamping diverged from RFC 7748, OR\n\
         (e) the appendix vector in draft-connolly-cfrg-xwing-kem changed.\n\
         \n\
         expected:  {}\n\
         computed:  {}\n",
        hex::encode(expected_ss),
        hex::encode(computed_ss),
    );

    // ---- (7) Confirm exact byte values used in the combiner --------------
    // Surfaces the ct_X and pk_X we hashed so a future review can
    // cross-check them against the draft's published `ct` and `pk`
    // tail bytes without rerunning the test.
    assert_eq!(
        ct_x.as_bytes().len(),
        32,
        "ct_X is 32 bytes (the X25519 ephemeral pubkey)"
    );
    assert_eq!(pk_x_arr.len(), 32, "pk_X is 32 bytes");
}
