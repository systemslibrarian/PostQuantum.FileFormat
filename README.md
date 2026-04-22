# PQF — Post-Quantum File Format

PQF is a specification and reference implementation for hybrid post-quantum encrypted files at rest.

[![CI](https://github.com/systemslibrarian/PostQuantum.FileFormat/actions/workflows/ci.yml/badge.svg)](https://github.com/systemslibrarian/PostQuantum.FileFormat/actions/workflows/ci.yml)

## Quick start

Install the preview CLI as a [.NET global tool](https://learn.microsoft.com/dotnet/core/tools/global-tools) (requires the .NET 8, 9, or 10 runtime):

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

> **Preview:** `pqf` is published as `0.4.0-preview.*`. The wire format is still draft v0.3.1 — files produced by previews are not guaranteed to be readable by `v1.0.0`.

## What this project is

- A **file format specification** ([spec/PQF-SPEC-v1.md](spec/PQF-SPEC-v1.md), draft v0.3.1).
- A **reference implementation** in .NET 8 ([src/PostQuantum.FileFormat](src/PostQuantum.FileFormat)).
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

- **Hybrid post-quantum encryption:** X25519 + ML-KEM-1024, combined through HKDF-SHA256 (`pqf1-concat-extract-v1`).
- **Hybrid signatures (optional):** Ed25519 + ML-DSA-87, fixed 4691-byte concatenated layout. If signed, both halves must verify.
- **Deterministic CBOR header** per RFC 8949 §4.2.2. Non-deterministic encodings are refused.
- **Chunked AES-256-GCM payload** with per-chunk HKDF-derived keys, fixed zero nonce, and AAD binding `file_id || chunk_index || is_final`.
- **Multi-recipient** in a single container, no payload duplication.
- **Two decryption modes:**
  - *Authenticated Mode* — plaintext is not released until the file signature (when present) and footer have verified.
  - *Streaming Mode* — plaintext may be released chunk-by-chunk on AEAD success, with explicit, non-silent post-hoc failure signaling.
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

## Repository structure

```
spec/                            Format definition and design rationale
  PQF-SPEC-v1.md                 Normative specification (v0.3.1 draft)
  PQF-DESIGN-RATIONALE-v1.md     Why the spec is what it is
src/PostQuantum.FileFormat/      Reference .NET implementation
cli/PostQuantum.FileFormat.Cli/  `pqf` command-line tool
tests/PostQuantum.FileFormat.TestVectors/
                                 Deterministic interoperability vectors
tests/PostQuantum.FileFormat.Tests/
                                 Validation, refusal, and roundtrip tests
tests/PostQuantum.FileFormat.Cli.Tests/
                                 CLI integration tests
docs/                            Release prep, checklist review, notes
SPEC-CHECKLIST.md                Per-section conformance checklist
```

## Security model

- **Confidentiality:** holds if *either* the classical (X25519) or post-quantum (ML-KEM-1024) primitive remains unbroken. A break of one half does not compromise the other.
- **Authenticity:** present only when the file is signed. When signed, both Ed25519 and ML-DSA-87 must verify; either failure refuses the file.
- **No anonymity guarantees.** PQF protects file contents at rest; it does not hide that a `.pqf` file exists, who the recipients are, or transport-layer metadata.
- **Metadata is visible.** The header is unencrypted and includes algorithm IDs, recipient public-key material, signer public keys (when signed), `chunk_size`, and `created` timestamp. Treat it as visible.
- **Implementation correctness matters.** The format is fail-closed by design, but security still depends on a correct implementation of the spec, the underlying KEM/AEAD/signature primitives, and the host OS's randomness source.

## Conformance philosophy

- **Strict parsing.** Unknown fields at any header level are refused. Permissive CBOR parsing is non-conforming.
- **Deterministic encoding required.** Headers must be re-encodable byte-for-byte; non-deterministic input is refused.
- **MUST-level enforcement.** Every `MUST` in the spec corresponds to a refusal path in the reader, exercised by negative test vectors and refusal-test suites.
- **No silent recovery.** There are no "best effort" paths. Any deviation from the spec terminates processing with an explicit, typed error.
- **Conformance is testable.** [SPEC-CHECKLIST.md](SPEC-CHECKLIST.md) enumerates the normative items. The implementation is gated against committed test vectors under [tests/PostQuantum.FileFormat.TestVectors](tests/PostQuantum.FileFormat.TestVectors).

## Current implementation limits

- The `PqfFileReader.OpenForValidation` path validates a fully materialized byte buffer with `int`-indexed offsets, so the validator is currently bounded by single-buffer size on the active .NET runtime even though the wire format uses `uint64` footer counters. A streaming validator path is planned and will not require a wire-format change.

## Status

- **Status:** Experimental. Specification is at draft v0.3.1.
- **Not externally audited.** No independent cryptographic review has been performed.
- **Not recommended for irreplaceable data.** The byte format is frozen only at v1.0.0; drafts may produce files that are not readable by the final release.
- **Latest preview:** [`v0.4.0-preview.2`](https://github.com/systemslibrarian/PostQuantum.FileFormat/releases/tag/v0.4.0-preview.2) on `main`, published to NuGet as [`PostQuantum.FileFormat.Cli`](https://www.nuget.org/packages/PostQuantum.FileFormat.Cli).

| Component | State |
|---|---|
| Specification | Draft v0.3.1 |
| Reference implementation (.NET) | Phases 1–5 complete on `main`, CI green |
| Test vectors | v1 set (positive + negative) committed |
| CLI (`pqf`) | `keygen`, `encrypt`, `decrypt`, `inspect`, `fingerprint`; published as `0.4.0-preview.2` on NuGet.org |
| Second-language implementation | Not started |
| External cryptographic review | Not started |

## Why this exists

Existing file-encryption formats either predate the post-quantum transition or treat post-quantum primitives as an optional extension. PQF starts from the assumption that confidential files written today may need to remain confidential against quantum-capable adversaries decades from now ("harvest now, decrypt later"), and that this should be the default rather than a bolt-on.

PQF is **spec-first, not implementation-first.** The specification is the source of truth; the .NET reference implementation exists to prove the spec is implementable and to provide a conformance baseline for a future second-language implementation. Where the implementation and spec disagree, the spec wins.

## Cryptographic review wanted

PQF is explicitly seeking review from cryptographers and post-quantum implementers on the following normative sections of [spec/PQF-SPEC-v1.md](spec/PQF-SPEC-v1.md):

- **§2.4** — Hybrid KEM combiner construction (HKDF salt/IKM layout, label binding).
- **§5.2** — Per-chunk AEAD construction and AAD binding (`file_id || chunk_index || is_final`).
- **§6.2 step 9** — File-signature coverage composition (`file_id || sha256(chunks) || footer`).
- **§6.3 step 7** — ML-KEM implicit-rejection timing and recipient-trial constant-time posture.
- **§6.4** — Authenticated vs Streaming Mode failure-signaling contract.

If you find an issue, please open a [GitHub Issue](https://github.com/systemslibrarian/PostQuantum.FileFormat/issues) or start a thread under [Discussions](https://github.com/systemslibrarian/PostQuantum.FileFormat/discussions). Reproducible refusal cases are especially welcome and will be folded into the negative test-vector set.

## License

MIT. See [LICENSE](LICENSE).
