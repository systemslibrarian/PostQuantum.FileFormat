# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Wire format and reference implementation are versioned independently —
see [`docs/COMPATIBILITY.md`](./docs/COMPATIBILITY.md) for the full
policy. Wire format changes are called out here under "Wire format."

## [Unreleased]

### Wire format — BREAKING

- **KEM combiner switched from PQF's in-house HKDF-concatenate-then-extract
  to X-Wing** (draft-connolly-cfrg-xwing-kem). This is a wire-incompatible
  break from spec v0.3.x; files produced under v0.3.x cannot be decrypted
  by v0.4.0+ readers, and vice versa. The file format version byte
  (`PQF1` magic, uint16 `0x0001`) does not change — only the `alg` map
  exact-match values and the recipient `pqc_ct` byte-string length.
  - `alg.combiner`: `"pqf1-concat-extract-v1"` → `"x-wing"`.
  - `alg.kem`: `"x25519+ml-kem-1024"` → `"x25519+ml-kem-768"`.
  - PQC slot: ML-KEM-1024 (Category 5) → **ML-KEM-768** (Category 3),
    required by the X-Wing parameter set.
  - `recipients[i].pqc_ct`: 1568 bytes → **1088 bytes**.
  - Canonical encryption public key total: 1601 bytes → **1217 bytes**
    (1 + 32 X25519 + 1184 ML-KEM-768).
  - DEK-wrap AEAD AAD: `file_id (16)` → `file_id (16) || recipient_index
    (u32 BE)`. X-Wing's combiner has no salt slot, so per-recipient
    binding moves into the AEAD AAD.
  - The bespoke `HkdfCombiner.DeriveKek` is removed; the per-chunk
    HKDF expansion (`DeriveChunkKey`) is unchanged.
  - All published v1 test vectors (TV-001..014 + TV-NEG-001..022) are
    regenerated under the new format.
- Spec doc version bumped to v0.4.0 (still pre-1.0.0 / EXPERIMENTAL).
  Motivation, exact construction, and a full changelog entry are in
  `spec/PQF-SPEC-v1.md` §2.1, §2.4, §4.2, §7.1.

### Added

- **CDDL formal schema** for the PQF v1 header
  (`spec/pqf-header.cddl`) with a CI job (`spec-validate.yml`) that
  validates every committed positive test vector against it.
- **Internet-Draft skeleton** in `spec/ietf/draft-clark-pqf-00.md`
  (kramdown-rfc source) as a community-review surface for the
  combiner construction.
- **Symbolic model** of the combiner under `spec/symbolic/` — Tamarin
  `.spthy` and ProVerif `.pv` files stating
  `dek_secrecy_under_hybrid_assumption`. Proofs are research-level
  follow-up.
- **Threat model** (`docs/THREAT-MODEL.md`) — explicit STRIDE table,
  per-asset analysis, scenarios, and what PQF deliberately does not
  promise.
- **Compatibility policy** (`docs/COMPATIBILITY.md`) — versioning
  contract, what freezes at v1.0.0, blocker list for v1.
- **Streaming guide** (`docs/STREAMING.md`) — when to use Streaming
  vs Authenticated Mode and the specific failure handling required.
- **Interoperability matrix** (`docs/INTEROP.md`) — living list of
  desired integrations and their current state.
- **MAINTAINERS.md** — single source for ownership, response-time
  expectations, and the 90-day coordinated-disclosure default.
- **Property-based tests** (FsCheck.Xunit) covering roundtrip
  identity (signed + unsigned), single-bit-flip refusal, truncation
  refusal, and per-recipient independence.
- **Fuzz harness** (`tests/PostQuantum.FileFormat.Fuzz`) over the
  deterministic-CBOR validator and the streaming pipeline. 60-second
  smoke pass in CI; OSS-Fuzz onboarding tracked separately.
- **NIST KAT cross-check harness**
  (`tests/PostQuantum.FileFormat.Kat`) consuming FIPS 203/204 KAT
  `.rsp` files via a `fetch-nist-kat.sh` placeholder.
- **Constant-time measurement scaffold**
  (`RecipientTrialConstantTimeTests`) — dudect-style Welch's t over
  the recipient-trial loop. Skipped by default until baseline noise
  is characterized.
- **Stress tests** for multi-GB plaintext and 1000-recipient
  containers, gated behind `--filter Category=Stress`.
- **Differential test** (`tests/PostQuantum.FileFormat.Differential`)
  generating 50 random valid containers and feeding them through
  both the .NET and Rust readers.
- **Rust writer crate** (`impl/rust/pqf-writer`) — full unsigned-
  encrypt path: X25519/ML-KEM/HKDF/AES-GCM/chunked AEAD/footer.
  Hybrid signing is the next contribution surface.
- **Bidirectional differential CI**
  (`differential-bidirectional.yml`) — Rust writer encodes random
  files, .NET reference reader decodes them.
- **Python binding** (`bindings/python`) — pyo3 wrapper over the
  Rust reader exposing `parse_header`, `decrypt`, and `Identity`.
- **WebAssembly binding** (`bindings/wasm`) with a browser demo at
  `bindings/wasm/demo/index.html`, deployable via
  `.github/workflows/pages.yml`.
- **BenchmarkDotNet harness** (`tests/PostQuantum.FileFormat.Bench`)
  with numbers in the README from a known-machine run.
- **Reproducible builds**: `Directory.Build.props` enables
  `Deterministic`, `ContinuousIntegrationBuild`, SourceLink, and a
  `PathMap` normalization. `reproducible-pack.yml` packs twice and
  verifies byte-identical output (modulo NuGet's psmdcp GUID
  filename, which is normalized).
- **Coverage** (`coverage.yml` + coverlet) with a Codecov badge.
- **OpenSSF Scorecard + CodeQL** weekly workflows.
- **Release pipeline**: CycloneDX SBOM + SLSA-L3 provenance via
  `slsa-github-generator` + NuGet push on tag.
- **CI matrix**: build + test + smoke on Ubuntu × Windows × macOS;
  runtime roll-forward matrix expanded to all three OSes × .NET 8/9/10.
- **JSON Schema** for `test-vectors/v1/manifest.json` plus a
  `manifest-validate.yml` CI job.
- **Repository hygiene**: `.gitattributes`, `.editorconfig`,
  CODEOWNERS, dependabot, CODE_OF_CONDUCT, CITATION.cff, FUNDING.yml,
  issue templates (bug / spec-review / refusal-case), PR template,
  PR labeler, label-sync workflow, stale-bot.
- **`pqf(1)` man page** at `man/pqf.1`.
- **Integration examples** at `examples/pqf-{encrypt,decrypt}-dir.sh`
  showing `tar | pqf encrypt` pipelines.

### Changed

- **Reproducible test-vector regeneration** now covers the full set
  (signed + unsigned). Previously only the unsigned subset was
  byte-deterministic; widening it required threading FIPS 204
  deterministic ML-DSA signing through `ICryptoProvider` and
  `HybridSigner`.

### Wire format

- **No breaking changes.** v0.3.1 draft. The header CDDL schema in
  `spec/pqf-header.cddl` matches the prose in
  `spec/PQF-SPEC-v1.md` §4 byte-for-byte.

## [0.4.0-preview.2] — 2026-02-13

### Changed

- CLI now ships with `<RollForward>Major</RollForward>` so the
  `dotnet tool install`-ed `pqf` runs on .NET 8, 9, or 10 without
  needing `DOTNET_ROLL_FORWARD=Major` set in the environment.

### Wire format

- No change.

## [0.4.0-preview.1] — 2026-02-12

### Added

- First public NuGet preview of `PostQuantum.FileFormat.Cli`.

### Wire format

- Draft v0.3.1 (unchanged from internal Phase 4 release).

[Unreleased]: https://github.com/systemslibrarian/PostQuantum.FileFormat/compare/v0.4.0-preview.2...HEAD
[0.4.0-preview.2]: https://github.com/systemslibrarian/PostQuantum.FileFormat/releases/tag/v0.4.0-preview.2
[0.4.0-preview.1]: https://github.com/systemslibrarian/PostQuantum.FileFormat/releases/tag/v0.4.0-preview.1
