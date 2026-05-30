# PQF Security Overview

This page is the reviewer front door for PQF v1. It states what the format
claims, what it does not claim, and where to read details.

## What PQF guarantees

- Confidentiality of payload bytes if either KEM half remains secure:
  X25519 or ML-KEM-1024.
- Integrity and authenticity are provided only when the file is signed.
  The hybrid signature requires both Ed25519 and ML-DSA-87 to verify.
- Fail-closed parsing and validation: malformed structure, unknown fields,
  deterministic-CBOR violations, AEAD failures, and algorithm mismatches are
  refused.

## What PQF does not guarantee

- No transport security: PQF is a file-at-rest format, not TLS/messaging.
- No anonymity or metadata privacy.
- Header metadata is plaintext and visible.
- Unsigned files carry no authenticity guarantee.
- On unsigned files, whole-payload erasure to an empty file is not
  cryptographically detectable (documented open question).

## Visible metadata (always plaintext)

- Version and algorithm identifiers.
- `chunk_size`, `created`, and `file_id`.
- Recipient count/order and each recipient block's public encapsulation data.
- Signer public keys when signatures are present.

## Named combiner relationship to X-Wing/CFRG

PQF (draft 0.5, `pqf1-bind-extract-v1`) uses concatenate-then-extract HKDF and
binds `file_id || recipient_index` in the HKDF-Extract salt. As of 0.5 it
**also folds the ML-KEM ciphertext (`pqc_ct`) and the X25519 ephemeral public
key (`classical_epk`) into the HKDF-Extract IKM**, binding the KEK to the exact
KEM transcript (the bind-extract combiner). This is in the spirit of X-Wing's
transcript binding, layered on top of:

- ML-KEM-1024 FO binding for the PQ shared secret, and
- per-recipient DEK-wrap AEAD substitution detection.

The construction is **not** byte-equivalent to X-Wing (HKDF-SHA-256 vs.
SHA3-256; `pqc_ct` folded explicitly), so X-Wing's proofs do not transfer
unchanged. See rationale §2.5.

## Open questions

- Dual-PRF treatment of the combiner assembly: see rationale question 2.
- Streaming post-hoc failure ergonomics and API contracts: see rationale
  question 3.
- Unsigned-file footer/truncation edge (whole-payload erasure to empty): see
  rationale question 7 and threat model STRIDE notes.
- Machine-checked proof of the exact combiner assembly (the symbolic models are
  research-level follow-up).

## Closed since earlier drafts

- **Signature domain separation** (was rationale question 6 / finding F1):
  resolved in draft 0.5 — header and file signatures now carry distinct
  `PQF1-header-sig-v1` / `PQF1-file-sig-v1` prefixes.
- **X-Wing/CFRG combiner ciphertext binding** (was rationale question 9 /
  finding F2): resolved in draft 0.5 — `pqc_ct` and `classical_epk` are folded
  into the combiner IKM.

## Where to start reading

1. `spec/PQF-SPEC-v1.md` for normative behavior and conformance requirements.
2. `spec/PQF-DESIGN-RATIONALE-v1.md` section 2 for cryptographic choices,
   section 11 for open questions.
3. `docs/THREAT-MODEL.md` for adversary model, STRIDE analysis, and explicit
   out-of-scope items.
4. `docs/STREAMING.md` for authenticated-vs-streaming release semantics.
5. `SPEC-CHECKLIST.md` and `test-vectors/v1` for conformance evidence.
