# PQF — Post-Quantum File Format

PQF is a specification and reference implementation for hybrid post-quantum encrypted files at rest.

[![CI](https://github.com/systemslibrarian/PostQuantum.FileFormat/actions/workflows/ci.yml/badge.svg)](https://github.com/systemslibrarian/PostQuantum.FileFormat/actions/workflows/ci.yml)
[![CodeQL](https://github.com/systemslibrarian/PostQuantum.FileFormat/actions/workflows/codeql.yml/badge.svg)](https://github.com/systemslibrarian/PostQuantum.FileFormat/actions/workflows/codeql.yml)
[![Differential](https://github.com/systemslibrarian/PostQuantum.FileFormat/actions/workflows/differential.yml/badge.svg)](https://github.com/systemslibrarian/PostQuantum.FileFormat/actions/workflows/differential.yml)
[![Reproducible pack](https://github.com/systemslibrarian/PostQuantum.FileFormat/actions/workflows/reproducible-pack.yml/badge.svg)](https://github.com/systemslibrarian/PostQuantum.FileFormat/actions/workflows/reproducible-pack.yml)
[![NuGet](https://img.shields.io/nuget/vpre/PostQuantum.FileFormat.Cli.svg?label=nuget%20%28pqf%29)](https://www.nuget.org/packages/PostQuantum.FileFormat.Cli/)
[![Downloads](https://img.shields.io/nuget/dt/PostQuantum.FileFormat.Cli.svg)](https://www.nuget.org/packages/PostQuantum.FileFormat.Cli/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Spec: draft v0.6.0](https://img.shields.io/badge/spec-draft%20v0.6.0-orange.svg)](spec/PQF-SPEC-v1.md)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/systemslibrarian/PostQuantum.FileFormat/badge)](https://securityscorecards.dev/viewer/?uri=github.com/systemslibrarian/PostQuantum.FileFormat)
[![codecov](https://codecov.io/gh/systemslibrarian/PostQuantum.FileFormat/branch/main/graph/badge.svg)](https://codecov.io/gh/systemslibrarian/PostQuantum.FileFormat)
[![REUSE compliant](https://img.shields.io/badge/REUSE-compliant-success.svg)](LICENSE)

## Quick start

Install the preview CLI as a [.NET global tool](https://learn.microsoft.com/dotnet/core/tools/global-tools) (requires the **.NET 10+ runtime** — the BCL native ML-KEM and ML-DSA APIs are mandatory):

```bash
dotnet tool install --global PostQuantum.FileFormat.Cli --prerelease
```

Then encrypt and decrypt a file end-to-end:

```bash
pqf keygen   --type encrypt --public-out alice.pub.pem --private-out alice.key.json
pqf encrypt  --in secret.pdf --out secret.pqf --recipient alice.pub.pem
pqf inspect  --in secret.pqf
pqf decrypt  --in secret.pqf --out secret.dec.pdf --identity alice.key.json --mode authenticated
```

> **Preview & scope:** `pqf` is published as `0.6.0-preview.*` as a **demonstration / dogfooding CLI** for the format and reference library — *not* a production library dependency. Its command surface, exit codes, and output shape are not a stability contract and may change between previews; projects building on PQF should depend on `PostQuantum.FileFormat` directly. The wire format is draft v0.6.0 (X-Wing + ML-KEM-768) and is **wire-incompatible** with v0.5.x and v0.3.x previews. Files produced by previews are not guaranteed to be readable by `v1.0.0`. See [`cli/README.md`](cli/README.md) for the full scope statement.

## How to try it

A self-contained roundtrip you can paste into a fresh shell. It creates a throwaway working directory, generates a sample plaintext, encrypts and signs it, inspects the container, decrypts in Authenticated Mode, and confirms the output matches the input byte-for-byte.

```bash
# 1. Install the CLI (skip if already installed)
dotnet tool install --global PostQuantum.FileFormat.Cli --prerelease

# 2. Set up a scratch directory
mkdir -p /tmp/pqf-demo && cd /tmp/pqf-demo

# 3. Generate a recipient encryption keypair and a signing keypair
pqf keygen --type encrypt --public-out alice.pub.pem  --private-out alice.key.json
pqf keygen --type sign    --public-out signer.pub.pem --private-out signer.key.json

# 4. Create a sample plaintext
echo "hello post-quantum world" > sample.txt

# 5. Encrypt and sign
pqf encrypt --in sample.txt --out sample.pqf \
  --recipient alice.pub.pem \
  --signing-key signer.key.json

# 6. Inspect the container without decrypting
pqf inspect --in sample.pqf

# 7. Decrypt in Authenticated Mode (verify before releasing plaintext)
pqf decrypt --in sample.pqf --out sample.out.txt \
  --identity alice.key.json \
  --mode authenticated

# 8. Confirm roundtrip
diff sample.txt sample.out.txt && echo "OK: roundtrip verified"
```

To clean up: `cd ~ && rm -rf /tmp/pqf-demo`.

## What this project is

- A **file format specification** ([spec/PQF-SPEC-v1.md](spec/PQF-SPEC-v1.md), draft v0.6.0).
- A **reference implementation** in .NET 10 ([src/PostQuantum.FileFormat](src/PostQuantum.FileFormat)).
- A **command-line tool**, `pqf` ([cli/PostQuantum.FileFormat.Cli](cli/PostQuantum.FileFormat.Cli)).
- A **deterministic-encoding, fail-closed parser** with no recovery paths.
- A **test-vector and conformance model** ([tests/PostQuantum.FileFormat.TestVectors](tests/PostQuantum.FileFormat.TestVectors)) used to gate the implementation against the spec.

## What this project is NOT

- Not TLS or any transport-security protocol.
- Not a messaging protocol.
- Not a disk- or volume-encryption scheme.
- Not an anonymity or metadata-privacy system.
- Not production-certified cryptography. The format and code have not undergone external cryptographic review.

## Core properties

- **Fail-closed by design:** any malformed structure, unknown field, reserved bit, length mismatch, or integrity failure results in immediate refusal with a typed error. There are no best-effort or permissive parsing paths.
- **Hybrid post-quantum encryption:** **X-Wing** (X25519 + ML-KEM-768) per draft-connolly-cfrg-xwing-kem, with external IND-CCA proofs in ROM/QROM (Barbosa et al., 2024). No bespoke combiner.
- **Hybrid signatures (optional):** Ed25519 + ML-DSA-87, fixed 4691-byte concatenated layout. If signed, both halves must verify.
- **Deterministic CBOR header** per RFC 8949 §4.2.2. Non-deterministic encodings are refused.
- **Chunked AES-256-GCM payload** with per-chunk HKDF-derived keys, fixed zero nonce, and AAD binding `file_id || chunk_index || is_final`.
- **Multi-recipient** in a single container, no payload duplication.
- **Two decryption modes:**
  - *Authenticated Mode* (default): verifies the file signature (when present) and footer before releasing any plaintext to the caller.
  - *Streaming Mode*: releases verified chunks as they are read, with explicit, non-silent post-hoc signaling if the footer or file signature fails to verify. Streaming failures cannot be silently ignored by the caller.
- **Fail-closed validation:** unknown fields, length mismatches, reserved bits, truncation, trailing bytes, and any algorithm deviation are refused. There are no permissive paths.

## 60-second example

```bash
# Generate a recipient encryption keypair
pqf keygen --type encrypt \
  --public-out alice.pub.pem \
  --private-out alice.key.json

# Generate a signing keypair
pqf keygen --type sign \
  --public-out signer.pub.pem \
  --private-out signer.key.json

# Encrypt and sign a file
pqf encrypt \
  --in secret.pdf \
  --out secret.pqf \
  --recipient alice.pub.pem \
  --signing-key signer.key.json

# Inspect header and footer metadata without decrypting
pqf inspect --in secret.pqf

# Decrypt in Authenticated Mode (verify before releasing plaintext)
pqf decrypt \
  --in secret.pqf \
  --out secret.dec.pdf \
  --identity alice.key.json \
  --mode authenticated
```

- `.pqf` is the encrypted container: `PQF1` magic, deterministic CBOR header, optional 4691-byte header signature, AES-256-GCM chunks, 20-byte footer, and an optional 4691-byte file signature.
- `pqf inspect` parses and prints the header and footer without touching plaintext.
- `--mode authenticated` buffers verification before any plaintext is released. `--mode streaming` releases verified chunks as they are read and surfaces post-hoc verification failures explicitly.

The resulting `.pqf` file is a self-contained encrypted container: it bundles recipient-wrapped keys, chunked ciphertext, integrity metadata, and optional hybrid signatures in a single byte stream.

## Repository structure

```
spec/                            Format definition and design rationale
  PQF-SPEC-v1.md                 Normative specification (v0.6.0 draft)
  PQF-DESIGN-RATIONALE-v1.md     Why the spec is what it is
  ietf/                          Internet-Draft skeleton (work in progress)
src/PostQuantum.FileFormat/      Reference .NET implementation
cli/PostQuantum.FileFormat.Cli/  `pqf` command-line tool
impl/rust/pqf-reader/            Second-source Rust reader + cross-impl gate
tests/PostQuantum.FileFormat.TestVectors/
                                 Deterministic interoperability vectors
tests/PostQuantum.FileFormat.Tests/
                                 Validation, refusal, and roundtrip tests
tests/PostQuantum.FileFormat.Cli.Tests/
                                 CLI integration tests
tests/PostQuantum.FileFormat.Fuzz/
                                 Lightweight parser fuzz harness
tests/PostQuantum.FileFormat.Kat/
                                 NIST KAT (FIPS 203 / FIPS 204) cross-check harness
examples/                        Short integration scripts (e.g. tar | pqf encrypt)
scripts/smoke.sh                 End-to-end roundtrip + refusal-path script (run by CI)
docs/                            Threat model, compatibility policy, side-channel posture
SPEC-CHECKLIST.md                Per-section conformance checklist
CONTRIBUTING.md                  How to file spec reviews, bugs, and PRs
SECURITY.md                      Security-reporting policy and supported versions
CODE_OF_CONDUCT.md               Contributor Covenant 2.1
```

## Security model

- **Confidentiality:** holds if *either* the classical (X25519) or post-quantum (ML-KEM-768) primitive remains unbroken. A break of one half does not compromise the other.
- **Authenticity:** present only when the file is signed. When signed, both Ed25519 and ML-DSA-87 must verify; either failure refuses the file.
- **No anonymity guarantees.** PQF protects file contents at rest; it does not hide that a `.pqf` file exists, who the recipients are, or transport-layer metadata.
- **Metadata is visible.** The header is unencrypted and includes algorithm IDs, recipient public-key material, signer public keys (when signed), `chunk_size`, and `created` timestamp. Treat it as visible.
- **Side-channel posture is inherited from the underlying primitives.** The reference implementation is wired to verify before release and to run the recipient trial in constant time over recipient blocks. ML-KEM-768 and ML-DSA-87 are supplied by the native BCL types ([`System.Security.Cryptography.MLKem`](https://learn.microsoft.com/dotnet/api/system.security.cryptography.mlkem) and [`MLDsa`](https://learn.microsoft.com/dotnet/api/system.security.cryptography.mldsa)) on .NET 10, which are platform-backed (Linux OpenSSL 3.5+ via libcrypto; Windows CNG on 11 / Server 2025) and the strongest practical side-channel posture available today. BouncyCastle stays as a dependency only for X25519, Ed25519, and the FIPS 204 *deterministic* ML-DSA signing path used in byte-deterministic test-vector regeneration — none of which the BCL exposes natively yet. The full per-operation matrix — what the wrapper controls and what it inherits — is documented in [docs/SIDE-CHANNEL-POSTURE.md](./docs/SIDE-CHANNEL-POSTURE.md).
- **Implementation correctness matters.** The format is fail-closed by design, but security still depends on a correct implementation of the spec, the underlying KEM/AEAD/signature primitives, and the host OS's randomness source.

## Conformance philosophy

- **Strict parsing.** Unknown fields at any header level are refused. Permissive CBOR parsing is non-conforming.
- **Deterministic encoding required.** Headers must be re-encodable byte-for-byte; non-deterministic input is refused.
- **MUST-level enforcement.** Every `MUST` in the spec corresponds to a refusal path in the reader, exercised by negative test vectors and refusal-test suites.
- **No silent recovery.** There are no "best effort" paths. Any deviation from the spec terminates processing with an explicit, typed error.
- **Conformance is testable.** [SPEC-CHECKLIST.md](SPEC-CHECKLIST.md) enumerates the normative items. The implementation is gated against committed test vectors under [tests/PostQuantum.FileFormat.TestVectors](tests/PostQuantum.FileFormat.TestVectors).

## Performance

Indicative numbers from a single-machine `BenchmarkDotNet` run on
.NET 8.0.27 / Windows 11. **Not a substitute for measuring on your
own hardware** — crypto throughput is dominated by primitive
implementations whose constant factors vary by CPU. The benchmark
project is `tests/PostQuantum.FileFormat.Bench`; the README in there
explains how to reproduce.

| Operation | 64 KiB | 1 MiB | 16 MiB |
|---|---:|---:|---:|
| `Encrypt_unsigned` (single recipient) | ~1.1 ms | ~2.2 ms | ~18 ms |
| `Decrypt_authenticated` (single recipient) | ~0.93 ms | ~2.3 ms | ~29 ms |
| `Parse_header_only` | ~9 µs (independent of plaintext size) | — | — |

At 16 MiB plaintext this is roughly **0.9 GiB/s encrypt and
0.6 GiB/s decrypt** on a single core, which is fast enough for
file-at-rest use cases and not fast enough for line-rate disk
streaming. The asymmetry — decrypt slower than encrypt — comes from
Authenticated Mode's verify-before-release contract: above its
threshold the reader stages plaintext to a 0600 tempfile so the file
signature can be verified before any byte is released.

Multi-recipient cost (64 KiB plaintext, same machine):

| Recipients | Encrypt | Decrypt as first | Decrypt as last |
|---:|---:|---:|---:|
| 1 | ~1.1 ms | ~0.98 ms | ~1.04 ms |
| 4 | ~2.8 ms | ~3.2 ms | ~3.2 ms |
| 16 | ~12.0 ms | ~10.4 ms | ~11.3 ms |
| 64 | ~41.3 ms | ~39.3 ms | ~39.9 ms |

Encrypt scales ~linearly in N as expected — one X25519/ML-KEM pair
per recipient. **Decrypt is also ~linear in N**, which is the
recipient-trial loop running over every block to keep the timing
independent of *which* recipient holds the DEK. The
"decrypt-as-first" vs "decrypt-as-last" gap is in the noise floor at
every N — that's the design working.

## Current implementation limits

- The legacy `PqfFileReader.OpenForValidation` helper still operates on a fully materialized byte buffer (preserved for tests and for callers who already have the file in memory). Production decryption now goes through `PqfStreamingPipeline`, which reads from a `Stream` directly: only the header (≤ 1 MiB per spec) and one in-flight chunk (≤ 16 MiB + AEAD tag) are buffered. Authenticated mode still stages plaintext to a 0600-mode `DeleteOnClose` tempfile above 100 MiB so the file signature can be verified before any byte is released to the destination — that staging is required by the security model, not by the parser.

## Status

- **Status:** Experimental. Specification is at draft v0.6.0.
- **Not externally audited.** No independent cryptographic review has been performed.
- **Not recommended for irreplaceable data.** The byte format is frozen only at v1.0.0; drafts may produce files that are not readable by the final release.
- **Latest preview:** [`v0.6.0-preview.3`](https://github.com/systemslibrarian/PostQuantum.FileFormat/releases/tag/v0.6.0-preview.3) on `main`, published to NuGet as [`PostQuantum.FileFormat.Cli`](https://www.nuget.org/packages/PostQuantum.FileFormat.Cli).

| Component | State |
|---|---|
| Specification | Draft v0.6.0 |
| Reference implementation (.NET) | Phases 1–5 complete on `main`, CI green |
| Test vectors | v1 set (positive + negative) committed; reproducibility gated on the unsigned subset |
| CLI (`pqf`) | `keygen`, `encrypt`, `decrypt`, `inspect`, `fingerprint`; published as `0.6.0-preview.3` on NuGet.org as a demonstration / dogfooding CLI ([scope](cli/README.md)) — not a production library dependency |
| Second-language implementation | Rust reader in `impl/rust/pqf-reader` + cross-impl conformance gate in CI |
| Parser fuzz harness | `tests/PostQuantum.FileFormat.Fuzz` (CBOR / header / streaming targets); 60-second CI smoke pass |
| NIST KAT cross-check | `tests/PostQuantum.FileFormat.Kat` scaffolded (verifies Decapsulate + Verify against FIPS 203/204 vectors when fetched) |
| Constant-time evidence | dudect-style measurement scaffold under `tests/PostQuantum.FileFormat.Tests/Crypto`; skipped by default until baseline noise is characterized |
| Supply-chain posture | OpenSSF Scorecard + CodeQL weekly; SLSA-L3 provenance + CycloneDX SBOM on release |
| Threat model | Published — see [`docs/THREAT-MODEL.md`](./docs/THREAT-MODEL.md) |
| Compatibility / freeze policy | Published — see [`docs/COMPATIBILITY.md`](./docs/COMPATIBILITY.md) |
| External cryptographic review | Not started |

## How PQF compares

This is a deliberately narrow comparison along the dimensions PQF cares
about. None of the rows are intended as criticism of the listed projects —
they have different goals, threat models, and audiences. PQF's distinguishing
choice is that *hybrid post-quantum confidentiality is the default*, not an
optional extension, and the parser is fail-closed by construction.

| Property | PQF (this project) | age | GPG (OpenPGP) | Tink | libsodium / NaCl box |
|---|---|---|---|---|---|
| Confidentiality primitives | X25519 **+ ML-KEM-768** via X-Wing (hybrid) | X25519 | RSA / ECDH (classical) | AEAD-only by default | X25519 |
| PQ posture | Hybrid PQ by default | None (classical) | None (classical) | None | None |
| Signatures | Optional hybrid: Ed25519 **+ ML-DSA-87** | None (encryption-only) | RSA / EdDSA (classical) | Signature primitives, classical | Ed25519 |
| Wire format | Deterministic CBOR (RFC 8949 §4.2.2) | Custom textual + binary | OpenPGP packet format (RFC 9580) | Protobuf (keyset), per-primitive ciphertext | Raw concatenation |
| Parser stance | Fail-closed, no recovery paths | Strict | Historically permissive | Strict | N/A (library, not a container) |
| Multi-recipient in one file | Yes | Yes | Yes | No (per-key API) | No |
| Streaming vs authenticated mode contract | Both, explicit non-silent failure signaling | Streaming | Streaming | API-level | API-level |
| Spec frozen? | Draft v0.6.0 (v1.0.0 target) | Stable | Stable (RFC) | Stable (Google) | Stable |
| External cryptographic audit | Not yet (review wanted) | Multiple reviews | Decades of scrutiny | Google + audits | Multiple reviews |

If you want a stable, audited classical format today, **age** is the right
choice for most file-at-rest cases. PQF is for callers who explicitly need
"this file should remain confidential against a quantum-capable adversary
decades from now, and I don't want a flag to forget."

## Why not just use age, S/MIME, or OpenSSL CMS?

The honest answer per alternative — what each one gives you, what it
doesn't, and the specific reason PQF exists alongside them.

### age (`age-encryption.org`)

**Use age** if your threat model is anything other than HNDL with
quantum capability. age is mature, audited multiple times, has a
cleanly specified format, and is the right answer for the
overwhelming majority of file-at-rest cases in 2026. Its X25519
confidentiality is excellent against today's adversaries.

**PQF differs in one specific way:** age is purely classical. A 2026
ciphertext encrypted with age becomes recoverable to whoever owns a
cryptographically-relevant quantum computer in 2035+. age has discussed
PQ extensions (e.g. `age-plugin-xwing` exists) but the format
itself is X25519-only by spec. PQF starts from "hybrid PQ is the
default, not a plugin" and pays for that with a bigger wire format,
younger primitives, and a smaller audited history.

### S/MIME (RFC 8551)

**Use S/MIME** if you are operating inside an established X.509 PKI
(corporate CA, certificate authorities, S/MIME-capable mail clients),
and your audience has S/MIME-capable readers.

**PQF differs in three significant ways:**

1. S/MIME is CMS-based, which is a TLV format with a long history of
   parser ambiguity and downgrade bugs (the format predates the
   modern fail-closed design discipline). PQF uses deterministic CBOR
   with a closed schema and refuses on any unknown field.
2. S/MIME has no standardized hybrid PQ profile. There are CMS
   extensions (`draft-ietf-lamps-cms-kemri`, `draft-ietf-lamps-pq-composite-kem`)
   that aim to fix this, but they are drafts; PQF is also a draft, but
   it picked a single standardized combiner (X-Wing) rather than
   creating its own.
3. S/MIME is bound to the X.509 ecosystem (issuer chains, CRLs / OCSP,
   subject DNs). PQF is keypair-only by design — no CA, no revocation
   semantics, no DN. That's a feature for some workflows and a missing
   feature for others.

### OpenSSL CMS (`openssl cms`)

**Use `openssl cms`** if you need a battle-tested CLI that produces
RFC 5652 CMS containers (the format S/MIME wraps) and you're willing
to manage the X.509 plumbing yourself.

**PQF differs in the same three ways as S/MIME**, plus a
parser-stance difference: OpenSSL's CMS parser has historically been
permissive (it has shipped fixes for malformed-input handling bugs as
recently as 2024). PQF's parser is fail-closed by design and rejects
any structural variation, including non-deterministic CBOR encoding
that would still round-trip to the same logical structure.

### PGP / GnuPG / OpenPGP (RFC 9580)

**Use OpenPGP** if your audience has GPG-shaped tooling
(Linux distros, Debian package signing, established PGP webs of
trust) and your threat model accepts classical-only confidentiality.

**PQF differs significantly:**

1. PGP is a packet format with decades of accumulated parser footguns;
   the IETF is on RFC 9580 specifically because of those. PQF's
   deterministic-CBOR-with-closed-schema is the modern version of
   that lesson.
2. PGP's PQ story is similar to S/MIME's: extension drafts exist
   (X-Wing in OpenPGP is being discussed at the IETF), but the format
   itself is classical. PQF picked the standardized X-Wing combiner
   and made hybrid PQ the default.
3. PGP's signature semantics carry web-of-trust baggage that PQF does
   not. PQF signatures only attest "this hybrid private keypair
   produced these signature bytes over this exact header / file." Any
   identity binding is the caller's responsibility.

### Why use PQF at all, then?

The narrow case where PQF is the right tool: **you want a file format
where (a) hybrid post-quantum confidentiality is the default not an
extension, (b) the parser refuses every form of malformed input by
construction not by convention, and (c) the implementation is small
enough to read end-to-end in an afternoon.** Outside that case, the
mature alternatives are better.

## Why this exists

Existing file-encryption formats either predate the post-quantum transition or treat post-quantum primitives as an optional extension. PQF starts from the assumption that confidential files written today may need to remain confidential against quantum-capable adversaries decades from now ("harvest now, decrypt later"), and that this should be the default rather than a bolt-on.

PQF is **spec-first, not implementation-first.** The specification is the source of truth; the .NET reference implementation exists to prove the spec is implementable and to provide a conformance baseline for a future second-language implementation. Where the implementation and spec disagree, the spec wins.

## Cryptographic review wanted

PQF is explicitly seeking review from cryptographers and post-quantum implementers. **Start here** if you're reviewing:

- [`spec/PQF-OVERVIEW.md`](./spec/PQF-OVERVIEW.md) — a 3-page reviewer overview that summarizes goals, threat model, primitives, wire format, and the five decisions worth focusing on. Read this first.
- [`spec/external-review/REVIEW-STATUS.md`](./spec/external-review/REVIEW-STATUS.md) — honest layer-by-layer record of what's been reviewed (X-Wing combiner ✅ inherited from upstream), what's been LLM-assisted only (⚠️), and what hasn't been touched yet (❌).

The normative sections most worth scrutiny in [spec/PQF-SPEC-v1.md](spec/PQF-SPEC-v1.md):

- **§2.4** — X-Wing combiner adoption (PQF 0.6 dropped the in-house `pqf1-bind-extract-v1` HKDF construction for the standardized X-Wing combiner from draft-connolly-cfrg-xwing-kem). KEK derivation is now `SHA3-256(ss_M || ss_X || ct_X || pk_X || XWING_LABEL)`. The in-tree implementation lives in [`XWingKem.cs`](src/PostQuantum.FileFormat/Crypto/XWingKem.cs). What review should focus on is the PQF-specific glue around X-Wing: per-recipient and per-file binding pushed to the DEK-wrap AEAD AAD (`file_id || recipient_index`) since the X-Wing combiner has no salt slot for either.
- **§5.2** — Per-chunk AEAD construction and AAD binding (`file_id || chunk_index || is_final`), with per-chunk-rekey + zero nonce.
- **§6.2 step 9** — File-signature coverage composition (`file_id || sha256(chunks) || footer`).
- **§6.3 step 7** — ML-KEM implicit-rejection timing and recipient-trial constant-time posture.
- **§6.4** — Authenticated vs Streaming Mode failure-signaling contract.

A running list of spec-level questions the author would value review on lives in [`spec/PQF-DESIGN-RATIONALE-v1.md` §11](./spec/PQF-DESIGN-RATIONALE-v1.md#11-open-questions-the-author-acknowledges).

**How to give feedback:**

- Quick reaction or pointer: open a [GitHub Issue](https://github.com/systemslibrarian/PostQuantum.FileFormat/issues) or start a thread under [Discussions](https://github.com/systemslibrarian/PostQuantum.FileFormat/discussions).
- Reproducible refusal cases: open an issue with the vector — these get folded into the negative test-vector set under [`test-vectors/v1/cases/TV-NEG-*.pqf`](./test-vectors/v1/).
- Security-sensitive findings: use the private channel in [`SECURITY.md`](./SECURITY.md).
- Want to verify the conformance claim yourself before reviewing? See [`test-vectors/QUICKSTART.md`](./test-vectors/QUICKSTART.md) — two commands, ~2 minutes, watches the independent Rust reader accept every .NET-written vector.

## Where to go next

- [`spec/PQF-SPEC-v1.md`](./spec/PQF-SPEC-v1.md) — the authoritative format specification and conformance rules.
- [`spec/PQF-DESIGN-RATIONALE-v1.md`](./spec/PQF-DESIGN-RATIONALE-v1.md) — why the spec is what it is; recommended reading before reviewing the format.
- [`spec/ietf/draft-clark-pqf-00.md`](./spec/ietf/draft-clark-pqf-00.md) — kramdown-rfc Internet-Draft skeleton, work in progress.
- [`docs/THREAT-MODEL.md`](./docs/THREAT-MODEL.md) — explicit threat model with a per-asset STRIDE table.
- [`docs/COMPATIBILITY.md`](./docs/COMPATIBILITY.md) — versioning policy, v1.0.0 freeze contract, deprecation rules.
- [`docs/DESIGN.md`](./docs/DESIGN.md) — long-form design narrative for non-cryptographers.
- [`docs/CLAIMS-AND-EVIDENCE.md`](./docs/CLAIMS-AND-EVIDENCE.md) — every security claim PQF makes, paired with the artifact that backs it.
- [`docs/FAQ.md`](./docs/FAQ.md) — common questions with hyperlinked answers.
- [`docs/STREAMING.md`](./docs/STREAMING.md) — decision matrix for Streaming vs Authenticated Mode.
- [`docs/INTEROP.md`](./docs/INTEROP.md) — living interoperability matrix.
- [`docs/SIDE-CHANNEL-POSTURE.md`](./docs/SIDE-CHANNEL-POSTURE.md) — per-operation side-channel posture (what the wrapper controls, what it inherits, what's out of scope).
- [`CHANGELOG.md`](./CHANGELOG.md) — Keep-a-Changelog history.
- [`MAINTAINERS.md`](./MAINTAINERS.md) — who owns what, response-time expectations, disclosure window.
- [`man/pqf.1`](./man/pqf.1) — manual page (`mandoc man/pqf.1`).
- [`SPEC-CHECKLIST.md`](./SPEC-CHECKLIST.md) — per-section conformance items enumerated from the spec.
- [`docs/internal/PHASE-NOTES.md`](./docs/internal/PHASE-NOTES.md) — implementation phase notes including any spec-ambiguity decisions made during the reference build.
- [`CONTRIBUTING.md`](./CONTRIBUTING.md) — how to file spec reviews, bugs, and PRs; what gets accepted and what doesn't.
- [`SECURITY.md`](./SECURITY.md) — how to report security-sensitive findings (private security advisory channel for exploitable issues).
- [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md) — community standards.
- [`examples/`](./examples/) — short scripts that show how PQF composes with familiar Unix pipelines (`tar | pqf encrypt`).
- [`scripts/smoke.sh`](./scripts/smoke.sh) — end-to-end roundtrip + refusal-path script run by CI; the simplest way to validate a local build.

## License

MIT. See [LICENSE](LICENSE).
