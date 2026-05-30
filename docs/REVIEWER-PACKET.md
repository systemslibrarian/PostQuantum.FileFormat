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
| Cross-impl KAT against the X-Wing draft's published test vector | **RESOLVED in 0.6.0-preview.2** — `impl/rust/pqf-writer/tests/xwing_draft_kat.rs` replays draft-connolly-cfrg-xwing-kem Appendix C example 1 through the same crypto stack PQF uses and asserts byte-equal `ss`. This KAT immediately caught a real bug (label position) in preview.1; see CHANGELOG. | `impl/rust/pqf-writer/tests/xwing_draft_kat.rs` |
| Symbolic / machine-checked proof of the overall assembly | **OPEN at the assembly level** — X-Wing combiner is externally proven; the full PQF stack (X-Wing + per-recipient AEAD wrap + chunked AEAD + hybrid sigs + footer) is not yet end-to-end modelled. The pre-0.6 symbolic models in `spec/symbolic/` were specific to the old combiner and are marked superseded | spec §13; `spec/symbolic/README.md` |

## How to reproduce the evidence

Prerequisites: .NET 8/9/10 SDK; a Rust toolchain (`cargo`).

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

## Dependency posture (owning the BouncyCastle reality)

The .NET reference implementation uses **BouncyCastle 2.6.2** (pinned exact
in `src/.../PostQuantum.FileFormat.csproj`) as its source of ML-KEM-768 /
ML-DSA-87 / Ed25519 / X25519 primitives on .NET 8 and .NET 9. On .NET 10+,
`CryptoProvider.Detect()` switches to the BCL native
`System.Security.Cryptography.MLKem` / `MLDsa` implementations; both code
paths are kept in lock-step by `CryptoProviderParityTests`, which generates
keys on one stack, encapsulates on the other, and asserts byte-identical
shared secrets and signatures.

The honest version of "what this means for side channels": BouncyCastle's
managed ML-KEM and ML-DSA are not written to be constant-time against
power, EM, or microarchitectural attackers — they are written to be
correct and portable. The wrapper code in this repo IS written to be
constant-time over the recipient-trial loop (`AuthenticatedModeDecryptor.
ResolveDek`) and over the hybrid-signature verification (`HybridSigner.
Verify` uses bitwise `&` not short-circuit `&&`). What we control:
constant-time wrappers; what we inherit: whatever the primitive provides.

For a 2026 archival file format this is the weakest remaining link, and we
say so plainly. The `BclCryptoProvider` exists so that on platforms where
the BCL provides hardware-backed constant-time primitives (.NET 10+
on Windows Server 2025 / Windows 11, or Linux/macOS with OpenSSL 3.5+),
those primitives are used in preference. See
[`docs/SIDE-CHANNEL-POSTURE.md`](./SIDE-CHANNEL-POSTURE.md) for the full
per-primitive breakdown.

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
2. **A C# port of the X-Wing draft KAT.** The Rust KAT
   (`impl/rust/pqf-writer/tests/xwing_draft_kat.rs`) now validates the
   combiner against the draft Appendix C vector and caught a real bug
   in preview.1. Porting the same `(pk, eseed, ss)` fixture into a C#
   `XWingKem_DraftKAT` test would make the .NET implementation
   independently self-evidencing, not just transitively-validated by
   sharing the formula with the Rust side. (Blocking issue: BouncyCastle
   2.6.2 does not expose ML-KEM deterministic encap with explicit
   randomness on its public API; the same trick the Rust KAT used
   needs either a BC internal-API hookup or a custom fake-RNG bridge.)
3. **GPG-signed tags and signed release artifacts** (the maintainer holds
   the key; this packet is unsigned).
4. A **published, attested release** with the SBOM + SLSA provenance the
   `release.yml` pipeline generates.
