# Symbolic model of the PQF hybrid KEM combiner

This directory contains a **work-in-progress symbolic model** of PQF's
hybrid KEM combiner construction (`pqf1-bind-extract-v1`, spec §2.4)
in the Tamarin Prover and ProVerif languages.

**Status: skeleton.** The model captures the structure of the combiner
and states the property we want to prove (DEK confidentiality holds as
long as either the classical or post-quantum half remains unbroken),
but the proofs themselves have not been completed by anyone with
formal-methods expertise. This directory is here so a cryptographer
who wants to contribute review has a concrete starting point — not
because the proofs already exist.

Why bother committing an incomplete model? Because the alternative is
no formal model at all, which is the more common state for new file
formats. A skeleton that is mechanically checkable for syntax errors
is closer to "real" than prose claims.

## Files

- [`pqf-combiner.spthy`](./pqf-combiner.spthy) — Tamarin model of the
  combiner. Captures: ephemeral X25519, ML-KEM encapsulation,
  HKDF-Extract over the bind-extract IKM (both shared secrets plus the
  ML-KEM ciphertext and X25519 ephemeral public key), AES-GCM wrap of
  the DEK under the resulting KEK. The lemma
  `dek_secrecy_under_hybrid_assumption` states the desired property.
- [`pqf-combiner.pv`](./pqf-combiner.pv) — Equivalent ProVerif applied
  pi calculus model for cross-checking. Same primitives, same property.

## What is and isn't modeled

In scope (this skeleton):

- The KEM combiner: bind-extract via HKDF (shared secrets concatenated
  with the ML-KEM ciphertext and X25519 ephemeral public key).
- DEK wrapping under the derived KEK.
- A passive Dolev–Yao adversary with full network control.

Out of scope (deliberate simplifications):

- The on-disk CBOR structure. The symbolic model treats messages
  abstractly; encoding correctness is a separate concern handled by
  the CDDL schema in `spec/pqf-header.cddl`.
- The hybrid signature scheme. Signatures provide authenticity, not
  confidentiality; modeling them is straightforward but orthogonal to
  the combiner question.
- The per-chunk AEAD construction. We assume an idealized AEAD oracle.
- Side channels. Symbolic models cannot express timing leaks; see
  `docs/SIDE-CHANNEL-POSTURE.md`.

## Running

Tamarin Prover (recommended on Linux/macOS; Windows via WSL):

```bash
# Install: https://tamarin-prover.com/manual/master/book/002_installation.html
tamarin-prover --prove spec/symbolic/pqf-combiner.spthy
```

ProVerif (cross-check):

```bash
# Install: https://bblanche.gitlabpages.inria.fr/proverif/
proverif spec/symbolic/pqf-combiner.pv
```

CI does not run these tools today. Wiring them up is straightforward
(Tamarin has a maintained Docker image) but adds ~10 minutes per run;
we will enable it once the proofs themselves type-check end-to-end.

## How to contribute

This is the part of the project where outside expertise has the most
leverage. If you have done symbolic protocol verification before:

- Open a [spec-review issue](../../.github/ISSUE_TEMPLATE/spec-review.yml)
  describing the gap you've found.
- Submit a PR refining the model. The bar is "the proof goes through
  in Tamarin or ProVerif with no unproven lemmas."

If a refinement reveals a flaw in the construction itself, that is a
spec defect — exactly the feedback the project asks for in the README's
"Cryptographic review wanted" section. Use the [private security
advisory](https://github.com/systemslibrarian/PostQuantum.FileFormat/security/advisories/new)
channel if exploitable.
