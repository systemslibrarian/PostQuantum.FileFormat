# PostQuantum.FileFormat

**Hybrid post-quantum file encryption for long-term archival.**

[![CI](https://github.com/systemslibrarian/PostQuantum.FileFormat/actions/workflows/ci.yml/badge.svg)](https://github.com/systemslibrarian/PostQuantum.FileFormat/actions/workflows/ci.yml)

> ⚠️ **DRAFT / EXPERIMENTAL** — This specification has not been reviewed by an
> independent cryptographer. Do not use to protect irreplaceable data. See
> [Status](#status) below.

PQF ("Post-Quantum File") is a file format and reference implementation for
encrypting files at rest to one or more recipients, using hybrid post-quantum
cryptography.

It is designed for long-term archival of files that must remain confidential
against both classical adversaries today and quantum adversaries decades from
now — the "harvest now, decrypt later" threat model.

## What PQF is

- A **single-file container format** for hybrid-PQ encryption at rest
- **Hybrid by default**: X25519 + ML-KEM-1024 for encryption,
  Ed25519 + ML-DSA-87 for optional signing
- **Multi-recipient**: one file, many recipients, no payload duplication
- **Streaming-safe**: bounded-memory encryption and decryption of files of
  arbitrary size
- **Fail-closed**: strict validation, no silent recovery
- **Versioned and specified**: the byte format is frozen once 1.0.0 ships

## What PQF is not

- Not a TLS replacement
- Not a messaging protocol
- Not a disk encryption scheme
- Not a full PGP replacement
- Not a key management system
- Not a certificate authority

## Status

| Component | Status |
|---|---|
| Specification | DRAFT v0.3.1 — seeking cryptographic review |
| Design rationale | DRAFT v0.1.0 |
| Reference implementation (.NET) | Phase 1 complete (foundations) |
| Test vectors | Not yet generated |
| CLI tool (`pqf`) | Not yet started |
| Second-language implementation | Not yet |
| External cryptographic review | Not yet |
| v1.0.0 release | Blocked on all of the above |

**Do not use PQF for real data until the status table is mostly green.** The
format may change in response to review feedback, and files produced by early
drafts may not be readable by the final v1 release.

## Repository layout

```
/spec/
  PQF-SPEC-v1.md              — The normative specification
  PQF-DESIGN-RATIONALE-v1.md  — Companion rationale document
/src/                          — Reference .NET implementation (coming)
/cli/                          — `pqf` command-line tool (coming)
/test-vectors/                 — Conformance test vectors (coming)
/docs/                         — Additional documentation
README.md                      — This file
LICENSE                        — MIT
```

## Seeking review

I am specifically seeking review from cryptographers on:

- §2.4 hybrid KEM combiner construction
- §6.2 step 9 signature coverage composition
- §5.2 per-chunk AEAD construction and AAD binding
- §6.3 step 7b ML-KEM implicit rejection timing behavior
- §8.8 deniability claim (is it bounded correctly?)

If you have expertise in hybrid post-quantum constructions, signed-container
formats, or AEAD mode design, I would be grateful for 30 minutes of your
attention on any of the above.

Contact: paul@systemslibrarian.dev

## Background

PQF is developed by Paul Clark ([@systemslibrarian](https://github.com/systemslibrarian)),
an application systems analyst at Leon County Public Library in Tallahassee,
Florida. It is a sibling project to
[secure-file-upload-dotnet](https://github.com/systemslibrarian/secure-file-upload-dotnet)
and the [crypto-lab educational demos](https://systemslibrarian.github.io/crypto-lab/).

The design draws on lessons from deploying production file-handling code in a
public library environment where retention horizons are long and the
"harvest now, decrypt later" threat model is plausible for certain classes of
records.

## License

MIT. See [LICENSE](LICENSE).

---

> *"So whether you eat or drink or whatever you do, do it all for the glory of God."* — 1 Corinthians 10:31
