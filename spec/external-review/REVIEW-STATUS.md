# PQF Review Status

**Last updated:** 2026-06-04
**Format version:** v1 0.6.0

A transparent record of what's been reviewed, by whom, with what
limitations. This document exists so reviewers — and users — can
calibrate the credibility of "PQF has been reviewed" claims against
what review actually consisted of.

## Summary

| Layer | Review type | Status |
|---|---|---|
| Hybrid KEM combiner (X-Wing) | External, formal | ✅ Inherited from upstream¹ |
| PQF-specific AAD-binding glue | None | ❌ Not reviewed |
| Hybrid signature composition (concat) | LLM-assisted only | ⚠️ Not externally reviewed |
| Per-chunk AEAD construction | LLM-assisted only | ⚠️ Not externally reviewed |
| File signature coverage | LLM-assisted only | ⚠️ Not externally reviewed |
| ML-KEM implicit-rejection handling | LLM-assisted only | ⚠️ Not externally reviewed |
| Deterministic CBOR enforcement rule | LLM-assisted only | ⚠️ Not externally reviewed |
| Wire format and parser robustness | Differential testing | ⚠️ Mechanical, not human |
| Side-channel / constant-time properties | Implementation library defaults | ❌ Not separately reviewed |

¹ X-Wing itself has IND-CCA proofs — classical in the ROM and
post-quantum in the standard model (Barbosa et al., 2024). PQF inherits
the combiner's proof for the secret-derivation step. It does NOT
inherit a proof for how PQF wraps that secret with file/recipient
binding at the AEAD layer.

## What "reviewed" has meant so far

### LLM-assisted review (drafting phase)

The spec was drafted iteratively with LLM-assisted review by Claude,
Grok, and ChatGPT. This caught real design issues — see the rationale
doc, §2.5 and elsewhere, for specific examples where Grok and ChatGPT
flagged the original in-house combiner. The current spec reflects
those revisions.

What this kind of review does well: catching obvious omissions,
suggesting tightening of normative language, spotting inconsistency
across sections, flagging well-known weaknesses (canonical-JSON
malleability, naive concat-then-extract combiners).

What this kind of review does not do: deliver original cryptographic
analysis, evaluate composition with respect to recent literature, or
substitute for someone who has spent a career building intuition for
where these constructions go wrong. Treat every LLM-assisted finding
as "worth investigating," never as "verified."

### Cross-implementation conformance (mechanical)

Two independent implementations exercise the same wire format:

- **.NET reference writer + reader** (BouncyCastle primitives,
  `src/PostQuantum.FileFormat`)
- **Rust reader and writer** (ml-kem 0.3, ml-dsa 0.1, x25519-dalek 2.0,
  aes-gcm 0.10, sha2 0.11, sha3 0.12, hkdf 0.13;
  `impl/rust/pqf-reader`, `impl/rust/pqf-writer`)

These share no code. They agree byte-for-byte on the published
v1 0.6 test vectors and on 50 random round-trip containers per CI run.
They also independently pass:

- The published X-Wing draft KAT (replay against
  draft-connolly-cfrg-xwing-kem appendix C, example 1)
- HKDF chunk-key derivation KAT
- AES-256-GCM AAD-binding KAT
- Reproducible test-vector regeneration

What this proves: the spec is implementable independently, and the
implementations agree on the wire format. Cross-impl agreement is the
strongest interop evidence the project has and is mechanical, not
opinion.

What this does NOT prove: that the wire format is the right one. Two
implementations of the same wrong design agree just as readily as two
implementations of the right design.

### Symbolic / formal-method explorations (incomplete)

Tamarin and ProVerif models exist in `spec/symbolic/` as exploratory
artifacts (`pqf-combiner.spthy`, `pqf-combiner.pv`). They are not
complete proofs of the full protocol and are not currently part of
CI. Treat them as "the author started here," not as verified results.

## What has not been reviewed

### Cryptographic — wanted before any 1.0 claim

- The composition of X-Wing's combiner output with the DEK-wrap AEAD
  AAD (`file_id || recipient_index`). The combiner inherits a proof;
  the AAD-binding step does not.
- Hybrid signature concatenation (Ed25519 || ML-DSA-87, no
  domain-separation tag between them). Common in practice; not
  separately analyzed for this construction.
- Per-chunk AEAD construction's behavior under partial-write,
  truncation, and recovery scenarios. The spec specifies refusal
  semantics; no one has poked at a real implementation looking for
  ways around them.
- Constant-time recipient-trial in the .NET and Rust references. The
  code does iterate every recipient regardless of match; whether the
  actual instruction stream is timing-independent depends on the
  primitive libraries (BouncyCastle, x25519-dalek, ml-kem) and has not
  been measured.
- Footer integrity when the file is unsigned. Spec §11 question #7 —
  acknowledged gap.

### Operational — wanted before any production claim

- A pen-test or red-team pass against a real implementation (header
  parser fuzzing, AEAD corruption, signature stripping, recipient
  manipulation).
- Side-channel measurement on a real machine, including cache and
  timing on the recipient-trial loop.
- Formal threat-model walk-through with someone whose day job is
  attacking file formats.

### Documentation — wanted before IETF submission

- Independent read of the IETF Internet-Draft for I-D conventions and
  IETF-house-style alignment.
- Confirmation that the deterministic CBOR enforcement rule is
  workable in major-language CBOR libraries (spec §11 question #1).

## How review feedback is incorporated

Every external finding to date has produced either a versioned spec
change (with a wire-format break if necessary) or an explicit
acknowledgment in the rationale doc. Examples:

- **0.6.0:** dropped the in-house `pqf1-bind-extract-v1` combiner for
  X-Wing after acknowledging the in-house construction had no formal
  treatment.
- **0.5.0:** added signature domain-separation prefixes
  (`PQF1-header-sig-v1` / `PQF1-file-sig-v1`).
- **0.3.0:** dropped canonical JSON in favor of deterministic CBOR
  after multiple reviewers flagged JSON canonicalization fragility;
  added explicit fail-closed refusal cases.
- **0.3.1:** tightened the deterministic-CBOR-enforcement rule.

The change log in `PQF-SPEC-v1.md` records each revision with its
motivating finding.

## Credit

When this document next updates, it will name (with permission) every
external reviewer who has provided substantive feedback. As of
2026-06-04 there are none yet to credit.

## How to contribute review

- Open a GitHub issue describing the finding, with section references.
- Or email <paul@systemslibrarian.dev> directly.
- If you'd prefer to publish a writeup first and have PQF link to it
  rather than have the finding only here, that's fine — say so and
  I'll wait.
