# PQF Reviewer Packet

One page, one target, one set of evidence. If you are reviewing PQF, start here.

## The frozen target

| What | Value |
|------|-------|
| Spec tag | `spec-v0.5` (draft, 2026-05-30) |
| Wire crypto profile | `pqf1-bind-extract-v1` (`alg.combiner`) |
| Conformance vector pack | `test-vectors/v1/` — 14 positive + 33 negative = **47** |
| Vector pack fingerprint | `sha256(SHA256SUMS) = ae682741243e6ee7b7a9e097241546076796c7c94913c0d8841334cbb48e4633` |
| Spec | [`spec/PQF-SPEC-v1.md`](../spec/PQF-SPEC-v1.md) |
| Rationale (the "why") | [`spec/PQF-DESIGN-RATIONALE-v1.md`](../spec/PQF-DESIGN-RATIONALE-v1.md) |
| One-page security model | [`docs/SECURITY-OVERVIEW.md`](./SECURITY-OVERVIEW.md) |
| Threat model | [`docs/THREAT-MODEL.md`](./THREAT-MODEL.md) |
| Every public claim → evidence | [`docs/CLAIMS-AND-EVIDENCE.md`](./CLAIMS-AND-EVIDENCE.md) |
| Normative MUST → portable vector map | [`SPEC-CHECKLIST.md`](../SPEC-CHECKLIST.md) §11 |

To verify the vector pack is the exact set described here:

```bash
cd test-vectors/v1 && sha256sum -c SHA256SUMS   # checks all 47 + manifest
sha256sum SHA256SUMS                            # must equal the fingerprint above
```

## What changed in draft 0.5 (read this if you saw 0.4)

0.5 is a draft wire-format change, gated by the `pqf1-bind-extract-v1`
combiner identifier (0.4 and 0.5 readers mutually refuse at the algorithm
check). Two cryptographic hardenings:

- **Bind-extract combiner** (§2.4): the HKDF-Extract IKM now folds
  `classical_epk` and `pqc_ct` alongside the two shared secrets, binding the
  KEK to the exact KEM transcript.
- **Signature domain separation** (§6.2): header and file signatures carry
  distinct `PQF1-header-sig-v1` / `PQF1-file-sig-v1` prefixes.

Wire *layout* (field order, lengths, version byte, CBOR structure) is
unchanged; only the bytes fed to the KDF and signer changed.

## Disposition of the v1 protocol debts

No reviewer should have to infer whether a limitation is an oversight, an
intentional tradeoff, or an open question. Each is labelled:

| Item | Disposition | Where |
|------|-------------|-------|
| KEM ciphertext / ephemeral transcript binding in the combiner | **RESOLVED in 0.5** — folded into HKDF-Extract IKM | spec §2.4; rationale §2.5, §11.9 |
| Header vs file signature domain separation | **RESOLVED in 0.5** — distinct prefixes | spec §6.2; rationale §11.6 |
| Unsigned files have no authenticity, incl. whole-payload erasure-to-empty | **ACCEPTED v1 tradeoff** — unsigned ≡ no authenticity by definition; sign the file to detect it | THREAT-MODEL STRIDE rows; rationale §11.7 |
| Streaming releases plaintext before final verification | **OPERATIONAL REQUIREMENT** — callers MUST honor the post-hoc result (`[MustUseReturnValue]`); Authenticated Mode is the buffered default | spec §6.4.2; `docs/STREAMING.md` |
| Machine-checked proof of the combiner assembly | **OPEN** — symbolic models are research-level, lemma stated not proved | `spec/symbolic/` |

## How to reproduce the evidence

Prerequisites: .NET 8/9/10 SDK; a Rust toolchain (`cargo`).

```bash
# 1. .NET reference: build + full test suite (expect 140 passed / 3 skipped, + 6 CLI)
dotnet test PostQuantum.FileFormat.sln -c Release

# 2. Regenerate the vector pack and prove it is byte-identical (determinism gate)
dotnet run --project tests/PostQuantum.FileFormat.TestVectors -c Release
git diff --exit-code test-vectors/v1/        # must be empty

# 3. Independent Rust reader against the committed vectors (expect 47/47)
cargo run --release --manifest-path impl/rust/pqf-reader/Cargo.toml \
  --bin pqf-conformance -- test-vectors/v1

# 4. Independent Rust writer -> .NET reader roundtrip (bidirectional interop)
cargo test --release --manifest-path impl/rust/pqf-writer/Cargo.toml --test roundtrip
```

CI runs all four on every push (`ci.yml`, `differential.yml`,
`differential-bidirectional.yml`, `spec-validate.yml`, `manifest-validate.yml`).

## Independent implementation status

- **Reader:** the Rust `pqf-reader` (`impl/rust/`) is a from-scratch second
  parser, gated against all 47 vectors in CI — it is not the code that wrote
  them.
- **Writer:** the Rust `pqf-writer` produces containers the .NET reference
  reader accepts (bidirectional differential gate, green). This closes the
  "reader-only interop" gap; a fully clean-room third-party implementation
  remains desirable.

## Dependency posture

| Dependency | Pin | Policy |
|------------|-----|--------|
| `BouncyCastle.Cryptography` | `2.6.2` (exact, `src/.../PostQuantum.FileFormat.csproj`) | Provides ML-KEM-1024 / ML-DSA-87 on .NET 8/9. On .NET 10+ the BCL native primitives are used instead (`CryptoProvider.Detect()`); both paths are parity-tested (`CryptoProviderParityTests`). Upgrades are reviewed against the NIST KAT cross-check (`tests/.../Kat`) before bumping. |

Reproducible builds: `Directory.Build.props` enables `Deterministic`,
`ContinuousIntegrationBuild`, SourceLink, `PathMap`; `reproducible-pack.yml`
packs twice and diffs.

## What this packet does NOT yet provide

These require action outside the repository and are the remaining distance to a
"10/10" review artifact (see `chatgptmore.md`):

1. **At least one external cryptographic review** of the combiner, the
   unsigned-erasure behavior, and the signature construction — the single
   highest-value remaining step.
2. **GPG-signed tags and signed release artifacts** (the maintainer holds the
   key; this packet is unsigned).
3. A **published, attested release** with the SBOM + SLSA provenance the
   `release.yml` pipeline generates.
