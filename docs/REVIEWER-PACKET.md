# PQF Reviewer Packet

One page, one target, one set of evidence. If you are reviewing PQF, start here.

## The frozen target

| What | Value |
|------|-------|
| Spec version | **draft 0.6.0** (2026-05-30) |
| Wire crypto profile | **`x-wing`** (`alg.combiner`) — draft-connolly-cfrg-xwing-kem |
| Hybrid KEM | X25519 + **ML-KEM-768** (`alg.kem` = `x25519+ml-kem-768`) |
| Hybrid signatures | Ed25519 + ML-DSA-87 (`alg.sig` = `ed25519+ml-dsa-87`), with `PQF1-header-sig-v1` / `PQF1-file-sig-v1` domain prefixes |
| AEAD | AES-256-GCM, chunked, per-chunk HKDF-Expand keys |
| Conformance vector pack | `test-vectors/v1/` — 14 positive + 33 negative = **47** |
| Vector pack fingerprint | `sha256(SHA256SUMS) = acf7876729ace1a8903cdc2916923d340d93dd2b4a0643201b007c41c2beedf9` |
| Spec | [`spec/PQF-SPEC-v1.md`](../spec/PQF-SPEC-v1.md) |
| Rationale (the "why") | [`spec/PQF-DESIGN-RATIONALE-v1.md`](../spec/PQF-DESIGN-RATIONALE-v1.md) |
| One-page security model | [`docs/SECURITY-OVERVIEW.md`](./SECURITY-OVERVIEW.md) |
| Threat model | [`docs/THREAT-MODEL.md`](./THREAT-MODEL.md) |
| Side-channel posture | [`docs/SIDE-CHANNEL-POSTURE.md`](./SIDE-CHANNEL-POSTURE.md) |
| Every public claim → evidence | [`docs/CLAIMS-AND-EVIDENCE.md`](./CLAIMS-AND-EVIDENCE.md) |
| Normative MUST → portable vector map | [`SPEC-CHECKLIST.md`](../SPEC-CHECKLIST.md) |

To verify the vector pack is the exact set described here:

```bash
cd test-vectors/v1 && sha256sum -c SHA256SUMS   # checks all 47 + manifest
sha256sum SHA256SUMS                            # must equal the fingerprint above
```

## What changed in draft 0.6 (read this if you saw 0.5)

0.6 is a wire-incompatible break from 0.5 that removes PQF's last
in-house cryptographic construction. 0.5 readers and 0.6 readers
mutually refuse at the algorithm-identifier check (`alg.combiner` and
`alg.kem` both change exact-match values).

- **KEM combiner is now X-Wing (§2.4).** The `pqf1-bind-extract-v1`
  HKDF construction that 0.5 introduced (itself an upgrade of the older
  `pqf1-concat-extract-v1` in response to review finding F2) is
  removed and replaced with the X-Wing combiner from
  draft-connolly-cfrg-xwing-kem:
  ```
  KEK = SHA3-256( ss_M || ss_X || ct_X || pk_X || "\.//^\" )
  ```
  where the label is the literal 6-byte ASCII art `5C 2E 2F 2F 5E 5C`
  (NOT the string "X-Wing"), `ss_M` is the ML-KEM-768 shared secret,
  `ss_X` is the X25519 shared secret, `ct_X` is the X25519 ephemeral
  public key, and `pk_X` is the recipient's X25519 long-term key.
  X-Wing has IND-CCA security proofs in the ROM and QROM published
  by Barbosa, Boyen, Connolly, Schwabe, Stehlé, and Strub (2024); PQF
  no longer carries a combiner that the project author wrote.
- **PQC parameter set: ML-KEM-1024 → ML-KEM-768** (§2.1). Required by
  the X-Wing parameter set; the rationale for trading Category 5 → 3
  is in `spec/PQF-DESIGN-RATIONALE-v1.md` §2.1.
- **Per-recipient binding moves layers** (§2.4 / §8.7). X-Wing's
  combiner has no salt slot for `file_id` / `recipient_index`, so the
  DEK-wrap AEAD's associated data now carries them explicitly:
  `aad = file_id (16) || recipient_index (uint32 BE)`. Cross-recipient
  and cross-file isolation properties are preserved one layer down.
- **Wire size deltas.** `pqc_ct`: 1568 → 1088 bytes. Canonical
  encryption public key: 1601 → 1217 bytes.
- **The 0.5 signature domain separation is preserved unchanged.**
  Header and file signatures still carry the distinct
  `PQF1-header-sig-v1` / `PQF1-file-sig-v1` prefixes that 0.5
  introduced.

Wire *layout* (field order, version byte, CBOR structure, footer,
signature lengths) is unchanged from 0.5.

## Disposition of the v1 protocol debts

No reviewer should have to infer whether a limitation is an oversight, an
intentional tradeoff, or an open question. Each is labelled:

| Item | Disposition | Where |
|------|-------------|-------|
| KEM ciphertext / ephemeral transcript binding in the combiner | **RESOLVED in 0.6** — X-Wing combiner binds `ct_X` and `pk_X` into the SHA3-256 input by construction | spec §2.4; X-Wing draft + Barbosa et al. (2024) |
| PQF maintaining its own KEM combiner | **RESOLVED in 0.6** — the in-house `pqf1-bind-extract-v1` is gone; combiner is standardized | spec §2.4; rationale §2.4–2.5 |
| Header vs file signature domain separation | **RESOLVED in 0.5** — distinct prefixes (preserved through 0.6) | spec §6.2; rationale §11.6 |
| Unsigned files have no authenticity, incl. whole-payload erasure-to-empty | **ACCEPTED v1 tradeoff** — unsigned ≡ no authenticity by definition; sign the file to detect it | THREAT-MODEL STRIDE rows; rationale §11.7 |
| Streaming releases plaintext before final verification | **OPERATIONAL REQUIREMENT** — callers MUST honor the post-hoc result (`[MustUseReturnValue]`); Authenticated Mode is the buffered default | spec §6.4.2; `docs/STREAMING.md` |
| Cross-impl KAT against the X-Wing draft's published test vector | **RESOLVED in 0.6.0-preview.2 (both impls)** — the X-Wing combiner is now validated against the published draft vector on both Rust (full KAT with deterministic ML-KEM in `impl/rust/pqf-writer/tests/xwing_draft_kat.rs`) and .NET (intermediate values from the same vector hard-coded in `tests/PostQuantum.FileFormat.Tests/Crypto/XWingKemTests.cs::XWingCombiner_MatchesPublishedDraftVector`). The Rust KAT covers the full encap path; the C# KAT covers the SHA3-256 invocation independently. This KAT immediately caught a real bug (label position) in preview.1; see CHANGELOG. | Both `xwing_draft_kat.rs` and `XWingKemTests.cs` |
| Symbolic / machine-checked proof of the overall assembly | **OPEN at the assembly level** — X-Wing combiner is externally proven; the full PQF stack (X-Wing + per-recipient AEAD wrap + chunked AEAD + hybrid sigs + footer) is not yet end-to-end modelled. The pre-0.6 symbolic models in `spec/symbolic/` were specific to the old combiner and are marked superseded | spec §13; `spec/symbolic/README.md` |

## How to reproduce the evidence

Prerequisites: **.NET 10 SDK**; a Rust toolchain (`cargo`).

```bash
# 1. .NET reference: build + full test suite
#    Expect: 145 passed / 3 skipped (PostQuantum.FileFormat.Tests) + 6 CLI.
dotnet test PostQuantum.FileFormat.sln -c Release

# 2. Regenerate the vector pack and prove it is byte-identical (determinism gate)
dotnet run --project tests/PostQuantum.FileFormat.TestVectors -c Release
git diff --exit-code test-vectors/v1/        # must be empty

# 3. Independent Rust reader against the committed vectors (expect 47/47)
cargo run --release --manifest-path impl/rust/pqf-reader/Cargo.toml \
  --bin pqf-conformance -- test-vectors/v1

# 4. Independent Rust writer → .NET reader roundtrip (bidirectional interop)
cargo test --release --manifest-path impl/rust/pqf-writer/Cargo.toml --test roundtrip
```

CI runs all four on every push (`ci.yml`, `differential.yml`,
`differential-bidirectional.yml`, `spec-validate.yml`, `manifest-validate.yml`).

## Independent implementation status

- **Reader:** the Rust `pqf-reader` (`impl/rust/`) is a from-scratch second
  parser, gated against all 47 vectors in CI — it is not the code that wrote
  them. Crypto stack: `ml-kem`, `x25519-dalek`, `sha3`, `aes-gcm`, `hkdf`.
- **Writer:** the Rust `pqf-writer` produces containers the .NET reference
  reader accepts (bidirectional differential gate, green). This closes the
  "reader-only interop" gap; a fully clean-room third-party implementation
  remains desirable.

## X-Wing combiner — KAT validation against the IETF draft

Both implementations are independently validated against the X-Wing IETF
draft's published test vector (draft-connolly-cfrg-xwing-kem,
Appendix C, example 1).

| Side | Test | What it proves |
|---|---|---|
| Rust | `impl/rust/pqf-writer/tests/xwing_draft_kat.rs` | Full deterministic encap path: draft `(pk, eseed) → (ct, ss)` byte-for-byte using `ml-kem` 0.2 (with the `deterministic` feature) + `x25519-dalek` + `sha3`. |
| C# | `XWingKemTests.XWingCombiner_MatchesPublishedDraftVector` | The SHA3-256 combiner step: pinned `(ss_M, ss_X, ct_X, pk_X)` from the Rust KAT → `XWingKem.ComputeCombiner` reproduces the draft's `ss = d2df0522…e384` byte-for-byte. |

Neither test relies on the other transitively. If either implementation's
combiner formula drifts (label position, byte order, label bytes, hash
function), the corresponding KAT fails loudly with a specific error message
naming the four possible causes. Both `ct_X` and `pk_X` in the C# fixture
are independently verifiable against the draft (last 32 bytes of the
published `ct` (1120 bytes) and `pk` (1216 bytes) respectively), so the
chain of custody is auditable without rerunning the Rust KAT.

**Why this matters.** When this KAT pair was first written, it immediately
caught a real bug: the X-Wing combiner label was prepended rather than
appended to the SHA3-256 input — a discrepancy that **every** existing
self-consistency / round-trip test had silently passed under because both
encap and decap used the same wrong formula. That fix shipped as
`0.6.0-preview.2`. The lesson — self-consistency tests are necessary but
not sufficient for cryptographic interop, and a KAT against a published
standard test vector is the only reliable way to catch this class of bug
— is the kind of evidence that distinguishes a serious project from a
self-confident one.

## Dependency posture (BCL native PQC; BouncyCastle as a leaf dep)

The .NET reference implementation targets **net10.0** only. ML-KEM-768
and ML-DSA-87 come from the native BCL types
`System.Security.Cryptography.MLKem` and
`System.Security.Cryptography.MLDsa` — compile-time references, no
reflection bridge, no legacy fallback. On the production path PQ
encap, decap, and sign all bottom out in platform crypto (Linux
OpenSSL 3.5+ via libcrypto; Windows CNG on 11 / Server 2025).

**BouncyCastle.Cryptography 2.6.2** (pinned exact in
`src/.../PostQuantum.FileFormat.csproj`) stays as a dependency only
because the BCL doesn't yet expose three pieces:

- X25519 (key gen + ECDH),
- Ed25519 (sign + verify), and
- FIPS 204 deterministic ML-DSA-87 signing (`rnd = 0`), which we use
  for byte-deterministic test-vector regeneration only.

None of these is on the harvest-now / decrypt-later attack surface;
the PQ primitives are. PQF's wrapper code is also written to be
constant-time over the recipient-trial loop
(`AuthenticatedModeDecryptor.ResolveDek`) and over the
hybrid-signature verification (`HybridSigner.Verify` uses bitwise `&`
not short-circuit `&&`). What we control: wrapper-level leakage. What
we inherit on the PQ path: platform crypto (the strongest practical
posture available in May 2026).

### Remaining migration notes — the two deliberate BouncyCastle usages

These are the two specific places BC still touches production code,
spelled out so a reviewer can confirm them in two minutes:

1. **X25519 / Ed25519 (`BouncyCastleCryptoProvider.X25519*` /
   `Ed25519*`).** The BCL's Curve25519 surface in .NET 10 is not
   uniform across the Windows / Linux / macOS matrix and some
   platforms don't expose primitive-level Curve25519 at all.
   Migrating these would either reintroduce a runtime-feature-detected
   fallback (the reflection bridge we just deleted for the PQ
   primitives) or accept non-uniform behavior across the CI matrix.
   Neither is acceptable for an archival format whose reproducibility
   gate depends on byte-identical output. **Classical-half side
   channels are not on the harvest-now/decrypt-later attack surface;
   PQ encap and PQ signing are — those go through the BCL native
   path.** The BC code path for the classical halves is accepted as
   the leaf-dep cost of cross-platform uniformity.
2. **Deterministic ML-DSA-87 signing
   (`MlDsa87SignDeterministic`, FIPS 204 with `rnd = 0`).** The BCL
   `MLDsa.SignData` overload on .NET 10 does not yet expose a
   randomness knob, so we can't ask the platform crypto for the
   `rnd = 0` variant. This path is **test-only** — used by
   `tests/PostQuantum.FileFormat.TestVectors` for byte-deterministic
   vector regeneration and by `reproducible-pack.yml`'s determinism
   gate. Production encrypt and sign callers never reach it.
   `BclCryptoProvider.MlDsa87SignDeterministic` is marked `internal`
   so it cannot surface through any public API by accident.

When the BCL ships a cross-platform Curve25519 / Ed25519 API **or** a
deterministic ML-DSA signing knob, both migrations follow the same
pattern as the ML-KEM / ML-DSA bridges in
`src/PostQuantum.FileFormat/Crypto/BclCryptoProvider.cs`. Until then,
these two paths are the documented scope of BouncyCastle in the
codebase.

See
[`docs/SIDE-CHANNEL-POSTURE.md`](./SIDE-CHANNEL-POSTURE.md) for the
full per-primitive breakdown.

We are **not** claiming PQF is hardened against side-channel attackers
who can measure timing, power, or EM emanations on the decrypting host.
We are claiming PQF doesn't add wrapper-level side channels on top of
whatever the primitive layer provides.

Reproducible builds: `Directory.Build.props` enables `Deterministic`,
`ContinuousIntegrationBuild`, SourceLink, `PathMap`; `reproducible-pack.yml`
packs twice and diffs.

## What this packet does NOT yet provide

These require action outside the repository and are the remaining distance
to a "10/10" review artifact:

1. **At least one external cryptographic review** of the X-Wing integration
   (the combiner itself is externally proven; what's not externally
   reviewed is PQF's overall assembly: per-recipient AEAD wrap, chunked
   AEAD with `is_final` AAD binding, footer reconciliation, hybrid
   signature construction with domain separation). This is the single
   highest-value remaining step.
2. ~~A C# port of the X-Wing draft KAT.~~ **Closed in 0.6.0-preview.2.**
   `XWingKemTests.XWingCombiner_MatchesPublishedDraftVector` pins the
   four intermediate values `(ss_M, ss_X, ct_X, pk_X)` extracted from
   the Rust KAT's deterministic encap path (the Rust KAT in turn
   replays draft-connolly-cfrg-xwing-kem Appendix C example 1) and
   asserts the C# `XWingKem.ComputeCombiner` reproduces the published
   `ss = d2df0522…e384` byte-for-byte. Both `ct_X` and `pk_X` are
   independently verifiable as the last 32 bytes of the draft's
   published `ct` and `pk` respectively.
3. **GPG-signed tags and signed release artifacts** (the maintainer holds
   the key; this packet is unsigned).
4. A **published, attested release** with the SBOM + SLSA provenance the
   `release.yml` pipeline generates.
