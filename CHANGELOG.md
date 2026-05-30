# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Wire format and reference implementation are versioned independently —
see [`docs/COMPATIBILITY.md`](./docs/COMPATIBILITY.md) for the full
policy. Wire format changes are called out here under "Wire format."

## [Unreleased]

### Changed

- **Bind-extract KEM combiner** (spec §2.4). The HKDF-Extract IKM now
  folds each recipient's X25519 ephemeral public key (`classical_epk`)
  and ML-KEM-1024 ciphertext (`pqc_ct`) alongside the two shared
  secrets, binding the KEK to the exact KEM transcript. Closes the
  ciphertext/ephemeral substitution gap previously left to the
  wrap-AEAD check (prior finding F2 / X-Wing-parity item).
- **Signature domain separation** (spec §6.2). The header and file
  signatures are now computed over `"PQF1-header-sig-v1" || header_bytes`
  and `"PQF1-file-sig-v1" || file_id || sha256(chunks) || footer`, so the
  two signing contexts are explicitly disjoint (prior finding F1).
- **Rust writer fixes** (found during the above): chunk frame order
  corrected to `length || flags || ct` per spec §5.3 (was
  `flags || length`), and the `rfc3339_known_values` test expectation
  corrected (the date function was right; the test constant was wrong).

### Wire format

- **Breaking (draft).** Spec advanced 0.4 → 0.5. The new `alg.combiner`
  identifier `pqf1-bind-extract-v1` gates the change: a 0.5 reader
  refuses 0.4 files and vice versa at the algorithm-identifier check.
  No change to wire *layout* (field order, lengths, version byte, CBOR
  structure) — only the bytes fed to the KDF and the signer changed.
  All 47 conformance vectors regenerated; .NET (140 tests) and the Rust
  `pqf-conformance` reader both pass 47/47 against the new crypto.

## [0.4.0-preview.3] — 2026-05-29

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

- **Pre-review hardening pass.** Addressed findings F1–F9 from the
  internal review (`findings.md`). Highlights:
  - `PqfFileWriter` now fills each non-final chunk with
    `ReadAtLeastAsync` so short-reading source streams (pipes,
    sockets) can no longer emit undersized non-final chunks (F5).
  - `HybridSigner.SignDeterministic` and the deterministic-randomness
    encrypt path are now `internal` test-only plumbing, with a
    reflection guard test asserting they are not reachable from the
    public `EncryptAsync` surface (F9).
  - Documentation sharpened for the truncation threat model,
    streaming "do not trust plaintext until final verification"
    contract, and the combiner's relationship to X-Wing/CFRG (F2, F3,
    F7, F8). New one-page reviewer front door at
    `docs/SECURITY-OVERVIEW.md`.
- **Header-schema conformance vectors** (`TV-NEG-023`…`TV-NEG-033`)
  added to the vector generator, closing the portable
  negative-vector gap for unknown-field (×4), algorithm mismatch,
  missing-field, empty-recipients, malformed `created`, invalid
  `chunk_size`, binary field length, and duplicate-CBOR-key refusals
  (F4). `SPEC-CHECKLIST.md` §11 now maps every fail-closed MUST to a
  portable vector. Manifest artifacts land once the
  `PostQuantum.FileFormat.TestVectors` project is re-run.
- **Reproducible test-vector regeneration** now covers the full set
  (signed + unsigned). Previously only the unsigned subset was
  byte-deterministic; widening it required threading FIPS 204
  deterministic ML-DSA signing through `ICryptoProvider` and
  `HybridSigner`.

### Wire format

- **No breaking changes.** Spec document advanced 0.3.1 → 0.4
  (reviewer-readiness milestone; tag `spec-v0.4`). The only normative
  clarification is the explicit parameter-set conformance note in §2.
  No wire-format, parameter, or normative-MUST change. The header CDDL
  schema in `spec/pqf-header.cddl` matches the prose in
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

[Unreleased]: https://github.com/systemslibrarian/PostQuantum.FileFormat/compare/v0.4.0-preview.3...HEAD
[0.4.0-preview.3]: https://github.com/systemslibrarian/PostQuantum.FileFormat/compare/v0.4.0-preview.2...v0.4.0-preview.3
[0.4.0-preview.2]: https://github.com/systemslibrarian/PostQuantum.FileFormat/releases/tag/v0.4.0-preview.2
[0.4.0-preview.1]: https://github.com/systemslibrarian/PostQuantum.FileFormat/releases/tag/v0.4.0-preview.1
