# Spec Checklist Review

## Scope

This review compares the current repository state on 2026-04-22 against
`SPEC-CHECKLIST.md` and identifies what appears complete, what is evidenced by
 tests, and what remains an explicit gap or release blocker.

Reference head:

- Commit: `3dd7507d9bb9e88647f9f458cd6dc3131d10f4a2`
- Branch: `main`

## Verified or strongly evidenced as implemented

### CBOR determinism

- Deterministic CBOR parse-strict validation is implemented.
- Non-shortest integers, indefinite lengths, duplicate keys, floating-point
  values, map ordering violations, and trailing bytes are refused.

### Header, file layout, and chunk processing

- Header schema validation enforces required fields, exact algorithm IDs,
  field lengths, and unknown-field refusal.
- File layout validation checks magic, version, header length, footer shape,
  and signature structural expectations.
- Chunk encryption/decryption follows the documented HKDF-derived per-chunk key,
  zero nonce, and AAD structure.

### Hybrid KEM, wrapping, and signatures

- KEK derivation follows the specified combiner labels and layout.
- Wrapped DEK handling uses AES-256-GCM with `file_id` as AAD.
- Hybrid signatures are fixed at 4691 bytes and require both halves to verify.

### Decryption-mode conformance

- Authenticated Mode is implemented.
- Streaming Mode is implemented with explicit result-based post-hoc failure
  signaling.
- Recipient trial iterates all recipient blocks and zeroes discarded secrets.

### Key formats and fingerprinting

- Canonical public-key binary formats are implemented with exact length and
  version-byte validation.
- PEM armor labels match the spec and output wraps at 64 characters.
- Fingerprint helpers produce lowercase SHA-256-based full and short forms.

### Conformance testing

- The repository contains a deterministic vector generator.
- The repository contains committed v1 vectors and a manifest-based conformance
  test.
- Signature-structure refusal coverage includes the previously deferred
  malformed header-signature-length case.
- CI passed on the current head after the Phase 4/5 push.

## Remaining gaps or release blockers

### 1. Checklist file is not maintained as a checked source of truth

`SPEC-CHECKLIST.md` still contains unchecked boxes throughout. The codebase and
tests now cover much of the checklist, but the checklist itself has not been
updated to reflect verified completion or intentional non-applicability.

Impact:

- Reviewers cannot use the checklist as an authoritative completion tracker.
- Release readiness still requires manual interpretation.

### 2. CLI packaging metadata is not release-ready

The CLI project is packable as a tool, but its package metadata is still local
development metadata:

- Package version is `0.0.0-local`

Impact:

- The CLI is buildable and testable, but not ready for a published tool
  release without choosing a real version and finalizing release metadata.

### 3. No tag or release baseline exists yet

The repository currently has no existing tags.

Impact:

- There is no established release/tag convention in git.
- A release still needs a chosen tag name, annotated tag message, and release
  notes publication step.

### 4. Final `v1.0.0` blockers remain outside implementation conformance

The repository README still identifies these non-implementation blockers:

- external cryptographic review
- second-language implementation

Impact:

- The implementation may be locally feature-complete through Phase 5, but the
  project is not yet positioned for a final stable `v1.0.0` claim.

## Recommended next actions

1. Update `SPEC-CHECKLIST.md` with verified completion marks and explicit notes
   for anything intentionally deferred or not applicable.
2. Replace CLI package version `0.0.0-local` with a real prerelease or release
   version.
3. Choose and document the repository's tag naming convention.
4. Publish a first tagged draft release only after the above items are settled.