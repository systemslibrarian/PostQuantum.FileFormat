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

## Named combiner deviation from X-Wing/CFRG

PQF v1 uses concatenate-then-extract HKDF over the two shared secrets and
binds `file_id || recipient_index` in HKDF-Extract salt.

PQF v1 does not include X-Wing-style ciphertext/public-key binding in the
combiner transcript. Instead it relies on:

- ML-KEM-1024 FO binding for the PQ shared secret, and
- per-recipient DEK-wrap AEAD substitution detection.

This is a deliberate v1 choice. X-Wing-parity transcript binding is tracked as
v1.1 roadmap work in the rationale open questions.

## Open questions

- Dual-PRF treatment of the v1 combiner assembly: see rationale question 2.
- Streaming post-hoc failure ergonomics and API contracts: see rationale
  question 3.
- Unsigned-file footer/truncation edge (whole-payload erasure to empty): see
  rationale question 7 and threat model STRIDE notes.
- Domain separation between header signature and file signature: see rationale
  question 6.
- X-Wing/CFRG combiner parity for ciphertext binding: see rationale question 9.

## Where to start reading

1. `spec/PQF-SPEC-v1.md` for normative behavior and conformance requirements.
2. `spec/PQF-DESIGN-RATIONALE-v1.md` section 2 for cryptographic choices,
   section 11 for open questions.
3. `docs/THREAT-MODEL.md` for adversary model, STRIDE analysis, and explicit
   out-of-scope items.
4. `docs/STREAMING.md` for authenticated-vs-streaming release semantics.
5. `SPEC-CHECKLIST.md` and `test-vectors/v1` for conformance evidence.
