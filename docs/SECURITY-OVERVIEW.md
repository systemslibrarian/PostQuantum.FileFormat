# PQF Security Overview

This page is the reviewer front door for PQF v1. It states what the format
claims, what it does not claim, and where to read details.

## What PQF guarantees

- Confidentiality of payload bytes if either KEM half remains secure:
  X25519 or ML-KEM-768.
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
- No hardening against side-channel attackers who can measure timing,
  power, or EM emanations on the decrypting host — PQF inherits whatever
  the underlying primitive provides. See [`docs/SIDE-CHANNEL-POSTURE.md`](./SIDE-CHANNEL-POSTURE.md).

## Visible metadata (always plaintext)

- Version and algorithm identifiers.
- `chunk_size`, `created`, and `file_id`.
- Recipient count/order and each recipient block's public encapsulation data.
- Signer public keys when signatures are present.

## Hybrid KEM combiner: X-Wing

As of draft 0.6, PQF uses the **X-Wing** combiner exactly as specified in
draft-connolly-cfrg-xwing-kem:

```
KEK = SHA3-256( ss_M || ss_X || ct_X || pk_X || "\.//^\" )
```

where the label is the literal 6-byte ASCII art `5C 2E 2F 2F 5E 5C` (NOT
the string "X-Wing"), `ss_M` is the 32-byte ML-KEM-768 shared secret,
`ss_X` is the 32-byte X25519 shared secret, `ct_X` is the 32-byte X25519
ephemeral public key, and `pk_X` is the recipient's 32-byte X25519
long-term public key.

X-Wing has IND-CCA security proofs in the ROM and QROM published by
Barbosa, Boyen, Connolly, Schwabe, Stehlé, and Strub (2024); the combiner
is no longer a PQF-author construction. The two pre-0.6 in-house
combiners — `pqf1-concat-extract-v1` (review finding F2's target) and
`pqf1-bind-extract-v1` (the 0.5 hardening of F2) — are both removed.

X-Wing's combiner has no salt slot, so PQF's per-file (`file_id`) and
per-recipient (`recipient_index`) binding moves to the DEK-wrap AEAD's
associated data: `aad = file_id (16) || recipient_index (uint32 BE)`.
Cross-recipient and cross-file isolation are preserved one layer down at
the AEAD.

## Open questions

- KAT validation of the X-Wing combiner against the
  draft-connolly-cfrg-xwing-kem published appendix test vector
  (`XWingKemTests` currently pins the byte-correct label and exercises
  binding properties in self-consistency; cross-draft KAT is the next test to
  land).
- Streaming post-hoc failure ergonomics and API contracts: see rationale
  question 3.
- Unsigned-file footer/truncation edge (whole-payload erasure to empty): see
  rationale question 7 and threat model STRIDE notes.
- Machine-checked proof of the *overall* PQF assembly (X-Wing combiner is
  externally proven; the full stack — per-recipient AEAD wrap + chunked
  AEAD + hybrid signatures with domain separation + footer — is not yet
  end-to-end modelled). The pre-0.6 symbolic models in `spec/symbolic/`
  modelled the (now-deleted) in-house combiner and are marked superseded.

## Closed since earlier drafts

- **X-Wing transition** (closes "PQF maintaining its own KEM combiner"):
  resolved in draft 0.6 — the in-house combiner is gone; the standardized
  X-Wing combiner replaces it byte-for-byte per
  draft-connolly-cfrg-xwing-kem.
- **Signature domain separation** (was rationale question 6 / finding F1):
  resolved in draft 0.5 — header and file signatures now carry distinct
  `PQF1-header-sig-v1` / `PQF1-file-sig-v1` prefixes. Preserved unchanged
  through 0.6.
- **X-Wing/CFRG combiner ciphertext binding** (was rationale question 9 /
  finding F2): resolved structurally in draft 0.6 — X-Wing's SHA3-256 input
  binds both `ct_X` and `pk_X` by construction. (0.5 had folded these into
  HKDF-Extract IKM as a transitional hardening; 0.6 removes the in-house
  HKDF combiner entirely.)

## Where to start reading

1. `spec/PQF-SPEC-v1.md` for normative behavior and conformance requirements.
2. `spec/PQF-DESIGN-RATIONALE-v1.md` section 2 for cryptographic choices,
   section 11 for open questions.
3. `docs/THREAT-MODEL.md` for adversary model, STRIDE analysis, and explicit
   out-of-scope items.
4. `docs/STREAMING.md` for authenticated-vs-streaming release semantics.
5. `SPEC-CHECKLIST.md` and `test-vectors/v1` for conformance evidence.
