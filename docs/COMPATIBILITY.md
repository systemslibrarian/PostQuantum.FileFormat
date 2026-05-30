# PQF Compatibility & Versioning Policy

This document is the public contract that callers can rely on when
deciding whether to adopt PQF, and what to expect across versions.

## TL;DR

- The wire format is currently **draft v0.6.0** (X-Wing + ML-KEM-768; shipped as `v0.6.0-preview.2`). It may change before v1.0.0.
- Once **v1.0.0** is published, the wire format is frozen. Every v1.x reader
  reads every v1.x file, forever.
- Pre-v1.0.0 files are not guaranteed to be readable by v1.0.0.
- Spec-level breaking changes after v1.0.0 require a major version bump
  (v2.0.0), which introduces a new magic and is parsed by a different
  reader path. v1 and v2 readers MUST refuse the wrong major version.

## Version planes

PQF tracks three independently versioned surfaces. They are NOT the same number.

| Plane | What it is | Versioned by | Frozen at |
|---|---|---|---|
| **Wire format** | The bytes on disk | Spec draft / final version | v1.0.0 |
| **Reference implementation** (.NET) | This codebase's libraries + CLI | SemVer NuGet version | Independent — bug-for-bug stability is **not** part of the format guarantee |
| **Specification document** | `spec/PQF-SPEC-v1.md` | Draft revisions, then `v1` (final) | Same date as wire format |

A bug fix in the reference implementation that changes the bytes it
produces for the *same logical input* is a spec violation, not an
implementation choice. We will not ship one.

## What "v1.0.0 freezes the wire format" means

- The four-byte magic `PQF1` is permanent. v2 will use a different magic.
- The CBOR header schema enumerated in `spec/PQF-SPEC-v1.md` §4 is closed.
  Unknown fields at any header level are refused by every conforming
  reader, today and forever.
- The signature layout (Ed25519 || ML-DSA-87, 4691 bytes concatenated)
  is fixed.
- The per-chunk AEAD construction, AAD binding, footer layout, and KEM
  combiner construction are fixed.

## What is NOT frozen at v1.0.0

- The reference implementation's public API surface (we'll SemVer it,
  but library shape may evolve).
- The CLI's command flags (we'll deprecate before removing).
- The set of test vectors. Vectors may be added; an existing vector
  may be renamed only with a transition period; no committed vector
  byte stream will ever be silently changed.
- The list of algorithm identifiers permitted in the header. New
  identifiers may be added for new primitives, but every reader MUST
  refuse identifiers it does not recognize (fail-closed by design).

## Pre-v1.0.0 (today)

- Files produced by `0.x` previews are **not** guaranteed to be readable
  by `v1.0.0`. Do not store irreplaceable data in pre-v1 files.
- Every draft bump is tagged on GitHub and surfaced in the README
  status table.
- Negative test vectors may be re-numbered between draft revisions if
  refusal-reason semantics tighten. The reasons themselves are
  considered part of the format contract.

## Path to v1.0.0

The current blockers are tracked in
`docs/RELEASE-PREP-*.md`. At a minimum, freezing v1.0.0 requires:

1. Resolution of the open spec questions in
   `spec/PQF-DESIGN-RATIONALE-v1.md` §11.
2. At least one external cryptographic review covering the combiner
   construction, AEAD chunking, and signature coverage. See README
   "Cryptographic review wanted."
3. A second-language reader implementation passing the full cross-impl
   conformance gate (the Rust reader under `impl/rust/` is the
   in-tree second source; a second writer is desired but not blocking).
4. Reproducible test-vector regeneration in CI — **both signed and
   unsigned vectors gated.** Two runs of the writer over the same
   seeded inputs produce byte-identical `.pqf` files because:
   Ed25519 is deterministic per RFC 8032 §5.1.6; ML-DSA-87 signing is
   threaded through the FIPS 204 deterministic variant (rnd = 0) via
   `ICryptoProvider.MlDsa87SignDeterministic`; the per-recipient KEM
   ciphertexts and AES-GCM nonces derive from an injectable RNG seeded
   from the test-vector ID. The cross-impl Rust reader gate exercises
   the same vectors end-to-end with an independent parser.

A v1.0.0 release will **never** be cut to clear a deadline. The wire
format only freezes when the open questions are resolved.

## Major versions (post-v1.0.0)

If a spec defect requires a wire-incompatible change, the next major
version (v2) introduces:

- A new four-byte magic (e.g. `PQF2`).
- A separate reader path. v1 readers MUST refuse v2 files; v2 readers
  MAY refuse v1 files (no "fall-through" parsing).
- A clearly stated migration path with a deprecation timeline for v1.

We will not silently widen the v1 schema, accept "v1-ish" files, or
add a permissive parsing mode under any circumstances. The fail-closed
posture is the format.

## Deprecation policy (reference implementation)

- Library API: minor versions may add; only major versions may remove.
  Removals get one minor cycle of `[Obsolete]` notice first.
- CLI flags: same policy. Help text continues to list deprecated flags
  for one major cycle, marked `(deprecated; use --new-flag instead)`.

## Reporting a compatibility break

If a file produced by an earlier release of the reference implementation
fails to read with a newer release within the same major version, that
is a bug. Open a [refusal-case issue](.github/ISSUE_TEMPLATE/refusal-case.yml)
with the failing bytes and the reader version.
