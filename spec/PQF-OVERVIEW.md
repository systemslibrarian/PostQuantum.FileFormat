# PQF in 10 Minutes — Reviewer Overview

**Status:** DRAFT / EXPERIMENTAL — do not protect irreplaceable data with v1.
**Document version:** 0.6.0 (2026-05-30).
**Companion to:** [`PQF-SPEC-v1.md`](./PQF-SPEC-v1.md) (normative, 1312 lines),
[`PQF-DESIGN-RATIONALE-v1.md`](./PQF-DESIGN-RATIONALE-v1.md) (688 lines),
[`ietf/draft-clark-pqf-00.md`](./ietf/draft-clark-pqf-00.md) (IETF I-D).

If you have 10 minutes, read this first. It exists so a busy reviewer can
decide whether the cryptographic core is worth a deeper look without paging
through 2,000 lines of spec.

---

## What PQF is

A single-file container for encrypting data at rest to one or more
recipients, **hybrid post-quantum by default**: every confidentiality
operation combines a classical KEM with a post-quantum KEM, and every
signature combines a classical signature with a post-quantum signature.
A break in either family alone does not compromise the file.

Mental model: PQF is to age / gpg / PKCS #7 enveloped data what age was to
PGP — smaller surface, opinionated, format-frozen — but with PQ baked into
v1 instead of bolted on as plugins.

## What PQF is not

- A TLS replacement, messaging protocol, or disk-encryption scheme.
- A general-purpose archive format (no multi-file, no compression).
- A solution for forward secrecy in the messaging sense.
- A privacy layer — the header is unencrypted; recipient public-key
  hashes are visible.
- A drop-in replacement for any existing format. v1 is wire-incompatible
  with everything, intentionally.

## Threat model in one paragraph

The motivating adversary is **harvest-now-decrypt-later**: a passive
attacker who archives ciphertext today and runs a CRQC against it in
twenty or thirty years. Files in scope are things that must remain
confidential across that horizon — medical records, legal archives,
classified research, library special collections, sealed court records.
Hybrid construction means confidentiality holds if *either* the classical
or the post-quantum primitive remains unbroken; an attacker needs both
broken to win. The trust boundary is the encrypting host's CSPRNG and a
correct primitive implementation; everything else PQF specifies is
fail-closed by construction.

---

## Primitives (v1, frozen)

| Slot | Primitive | Reference |
|---|---|---|
| Hybrid KEM | **X-Wing** = X25519 + ML-KEM-768 | draft-connolly-cfrg-xwing-kem; IND-CCA in ROM/QROM per Barbosa et al. 2024 |
| Hybrid signature | Ed25519 + ML-DSA-87 (concat: 64 + 4627 = 4691 bytes) | RFC 8032, FIPS 204 |
| Payload AEAD | AES-256-GCM, per-chunk-rekeyed | NIST SP 800-38D |
| KDF | HKDF-SHA-256 (chunk-key expansion); SHA3-256 (X-Wing combiner) | RFC 5869, FIPS 202 |
| Header encoding | Deterministic CBOR | RFC 8949 §4.2.2 |

Readers MUST refuse files that don't exactly match this primitive set.
Algorithm agility is by format-version bump, not by negotiation inside
v1.

## Wire format at a glance

```
+----------------------------------------+ offset 0
| Magic "PQF1" (4)                       |
| Version uint16 BE = 0x0001 (2)         |
| Header length uint32 BE (4)            |
+----------------------------------------+ offset 10
| Header: deterministic CBOR (N bytes)   |   { alg, chunk_size, created,
|                                        |     file_id, recipients[], signer? }
+----------------------------------------+
| Header signature (4691 bytes)          |   present iff signer != null
+----------------------------------------+
| Payload: sequence of chunks            |   each: len(4) || flags(1) || ct+tag
|                                        |   bit-0 of flags = is_final
+----------------------------------------+
| Footer (20 bytes)                      |   "PQFE" || chunk_count u64 BE
|                                        |   || plaintext_bytes u64 BE
+----------------------------------------+
| File signature (4691 bytes)            |   present iff signer != null
+----------------------------------------+ EOF
```

There is no padding, no trailing data, and no placeholder slots — absent
fields are absent, not zero-filled. A 1 MiB cap on the header prevents
oversized-header DoS while leaving comfortable room for ~100 recipients.

---

## The five decisions a reviewer should examine

If you're going to look closely at one part of the design, these are
where the substance lives. Each links to the full discussion.

### 1. X-Wing as the KEM combiner (§2.4)

`KEK_recipient = SHA3-256( ss_M || ss_X || ct_X || pk_X || "\.//^\" )`
where ss_M is the ML-KEM-768 secret, ss_X the X25519 secret, ct_X the
X25519 ephemeral public key (which X-Wing treats as a ciphertext), and
pk_X the recipient's X25519 long-term public key. This is the
construction defined and analyzed in draft-connolly-cfrg-xwing-kem —
PQF 0.6 cut over from a PQF-author in-house combiner
(`pqf1-bind-extract-v1`) to standardized X-Wing precisely so it could
inherit the proof.

### 2. Per-recipient + per-file binding pushed to AEAD AAD (§2.4)

X-Wing's combiner has no salt slot for the file instance or the
recipient slot. PQF binds those at the next layer instead:
`wrapped_dek_aad = file_id (16) || recipient_index (uint32 BE)`. A KEK
derived for recipient *i* cannot unwrap recipient *j*'s DEK wrap (AADs
differ); a KEK from one file cannot unwrap another file's wrap (file_id
differs). The cross-recipient and cross-file isolation properties are
preserved without modifying the combiner.

### 3. Per-chunk HKDF + zero nonce + `is_final` in AAD (§5.2)

Each chunk uses a fresh `chunk_key = HKDF-Expand(DEK, "PQF1-chunk-v1" ||
i (8 bytes BE), 32)` with a fixed 12-byte zero nonce. Safe under SP
800-38D §8.2 iff three invariants hold (all REQUIRED by the spec): DEK
freshness per file, monotonic in-order chunk indices, single-producer
writer. The per-chunk AAD includes file_id, chunk index, and an
`is_final` bit — so truncation is detected at AEAD verify, not just at
the footer.

### 4. Optional hybrid signatures over `file_id || sha256(chunks) || footer` (§6.2)

When present, the file signature commits to the file identity, the
exact chunk stream, and the footer in one pass. Truncation, chunk
substitution, and footer tampering are all signature-detectable in one
verification. Header and file signatures carry disjoint domain prefixes
(`PQF1-header-sig-v1`, `PQF1-file-sig-v1`, added in 0.5) so the two
signature messages cannot collide.

### 5. ML-KEM implicit-rejection handling for the recipient trial (§6.3, §8.8)

A reader walks every recipient slot in constant time regardless of
which one matches. ML-KEM's implicit rejection guarantees that
decapsulating a wrong-recipient ciphertext returns a pseudorandom
secret, so the AEAD tag — not the KEM result — is the sole signal of a
true match. The same property is the basis for the bounded "weak
deniability" claim in §8.8, which the spec deliberately states with
narrow language.

---

## Modes of decryption

PQF defines two normative reader modes (§6.4):

- **Authenticated Mode** — verify every signature and AEAD tag *before*
  emitting any plaintext. Required for archival; default for new code.
- **Streaming Mode** — emit plaintext as it verifies, before the
  file-level signature is checked. Permitted, but the spec is strict:
  if any post-hoc check fails, the reader MUST signal failure to the
  consumer in a way that cannot be silently swallowed. "Logged it" is
  explicitly non-conforming.

The distinction matters because the chunked AEAD lets you start emitting
plaintext at chunk 0, but the file-level signature (if present) covers
the whole chunk stream. Streaming mode is a deliberate tradeoff against
the bounded-memory requirement, not an oversight.

---

## What has been done

| | Status |
|---|---|
| Normative spec (1312 lines, version 0.6.0) | shipped |
| Companion design rationale (688 lines, sections 1–12 + §10 reviewer guide + §11 open questions) | shipped |
| IETF Internet-Draft (`draft-clark-pqf-00`) | drafted, not submitted |
| Machine-checkable CDDL header schema | shipped, enforced in CI |
| Reference .NET writer + reader (BouncyCastle) | shipped |
| Independent Rust reader (ml-kem 0.3, ml-dsa 0.1, x25519-dalek 2, aes-gcm 0.10) | shipped |
| Independent Rust writer (same crate set; for differential testing) | shipped |
| Python binding (maturin) | shipped |
| WASM bundle (`.github/workflows/pages.yml`) | shipped |
| Cross-implementation conformance suite (Rust reader ↔ .NET vectors, 8 cases + 50 random containers) | shipped, in CI |
| X-Wing draft KAT replay against published IETF vectors | shipped, in CI |
| KAT vectors for HKDF chunk-key derivation, AEAD construction | shipped |
| Reproducible test-vector regeneration | shipped, in CI |

Independent implementations exercising the same wire format are the
single most credible interop evidence the project has. The Rust reader
and the .NET writer share no code; their agreement on every test vector
is mechanical, not coincidental.

## What has *not* been done

- **No external cryptographic review.** All review to date has been
  internal or LLM-assisted (Grok, ChatGPT). This document exists to
  invite real review.
- **No formal security proof of the AAD-binding construction.** The
  AAD-side binding (§2.4 second half) is straightforward but
  unreviewed. The KEM combiner itself inherits X-Wing's proof; the
  PQF-specific glue does not yet have one.
- **No public security audit.** No NCC, Cure53, Trail of Bits, etc.
  involvement.
- **Side-channel posture is inherited from libraries.** PQF specifies
  constructions, not constant-time implementations.
- **No IETF submission.** The I-D in `spec/ietf/` is drafted; whether
  to submit depends partly on the response to this document.

---

## Open questions the author would value review on

From `PQF-DESIGN-RATIONALE-v1.md` §11, in priority order:

1. **Combiner sufficiency.** Is `SHA3-256(ss_M || ss_X || ct_X || pk_X ||
   label)` plus AAD-binding strong enough for the multi-recipient
   archival threat model, or is there a known stronger construction
   that's still simple?
2. **Deniability framing.** §8.8 claims *weak* deniability deliberately.
   Is the claim correctly bounded — neither over- nor under-stated?
3. **Footer integrity on unsigned files.** Signed files cover the footer
   via the file signature; unsigned files rely on structural checks. Is
   that gap worth closing in v1.1 via AEAD-binding the footer?
4. **Constant-time recipient trial.** Does the spec's prose make the
   constant-time-over-recipients requirement implementable, or is
   tightening needed?
5. **Deterministic CBOR in the wild.** The spec requires *enforcement*,
   not just *production*. Is the "parse-strict OR re-encode-and-compare"
   rule workable across major-language CBOR libraries?

## Where to go from here

- **Full spec:** [`PQF-SPEC-v1.md`](./PQF-SPEC-v1.md)
- **Design rationale (why each decision):** [`PQF-DESIGN-RATIONALE-v1.md`](./PQF-DESIGN-RATIONALE-v1.md)
- **IETF Internet-Draft:** [`ietf/draft-clark-pqf-00.md`](./ietf/draft-clark-pqf-00.md)
- **CDDL header schema:** [`pqf-header.cddl`](./pqf-header.cddl)
- **Conformance test vectors:** [`test-vectors/v1/`](../test-vectors/v1/)
- **Reference implementations:** `src/` (.NET), `impl/rust/` (Rust)

Contact: **Paul Clark** &lt;paul@systemslibrarian.dev&gt;.
Review feedback is welcomed by email, by GitHub issue, or by PR.
