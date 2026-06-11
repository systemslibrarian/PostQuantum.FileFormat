# Symbolic model of the PQF hybrid KEM combiner

> **Superseded as of spec v0.4.0 (2026-05-30).**
> The model files in this directory describe PQF's previous in-house
> KEM combiner, `pqf1-concat-extract-v1`, which was **removed** when
> PQF migrated to the X-Wing combiner
> (draft-connolly-cfrg-xwing-kem). X-Wing has external security proofs
> — classical IND-CCA in the ROM and post-quantum IND-CCA in the
> standard model — published by Barbosa, Connolly, Duarte, Kaiser,
> Schwabe, Varner, and Westerbaan (2024) — there is no longer anything
> for PQF to model at the KEM-combiner layer.
>
> The files are left in place for historical reference and because
> their structural shape (KEM → KDF → AEAD-wrap) is a useful starting
> point if anyone later wants to model the *outer* PQF assembly
> (per-recipient wrap + chunked AEAD + hybrid signatures). They are
> **NOT a normative artifact** of the current spec.

## Original (pre-v0.4.0) status

This directory contained a **work-in-progress symbolic model** of
PQF's hybrid KEM combiner construction
(`pqf1-concat-extract-v1`, spec §2.4 pre-v0.4.0) in the Tamarin
Prover and ProVerif languages.

**Status (frozen): skeleton.** The model captured the structure of
the combiner and stated the property to prove (DEK confidentiality
holds as long as either the classical or post-quantum half remains
unbroken), but the proofs themselves were never completed.

## Files

- [`pqf-combiner.spthy`](./pqf-combiner.spthy) — Tamarin model of the
  legacy combiner. Captures: ephemeral X25519, ML-KEM encapsulation,
  HKDF-Extract over the concatenation, AES-GCM wrap of the DEK under
  the resulting KEK. The lemma `dek_secrecy_under_hybrid_assumption`
  stated the desired property.
- [`pqf-combiner.pv`](./pqf-combiner.pv) — Equivalent ProVerif applied
  pi calculus model for cross-checking.

## Why keep them at all

Two reasons:

1. **Provenance.** When reviewers ask "what about that symbolic model
   you committed?", the answer is "it modeled the v0.3.x combiner,
   which we removed when we adopted X-Wing — see the deprecation
   notice above." Deleting the files would erase that audit trail.
2. **Future starting point.** If someone wants to model PQF's *outer*
   assembly (X-Wing as an idealized KEM, then the per-recipient AEAD
   wrap, then chunked AEAD, then hybrid signatures), the
   `pqf-combiner.spthy` Tamarin file is a structural template for how
   to wire up Dolev–Yao adversaries against PQF-shaped protocols.

For the X-Wing combiner itself, the right references are:

- draft-connolly-cfrg-xwing-kem (the spec).
- Barbosa, Connolly, Duarte, Kaiser, Schwabe, Varner, Westerbaan (2024)
  — "X-Wing: The Hybrid KEM You've Been Looking For", Communications in
  Cryptology (IACR ePrint 2024/039) — IND-CCA proofs in the ROM
  (classical) and the standard model (post-quantum).
