# PQF Security Considerations (consolidated)

**Status:** companion to [`PQF-SPEC-v1.md`](./PQF-SPEC-v1.md) §8 and to the
[IETF Internet-Draft](./ietf/draft-clark-pqf-00.md) Security
Considerations section. Where this document and `PQF-SPEC-v1.md` §8
disagree, **the spec wins**.

**Document version:** 0.6.0 (2026-06-04).

This document re-presents PQF's security argument in IETF-style
"assumed primitive properties → claimed file-level guarantees →
construction argument → known gaps" form so that an external reviewer
can evaluate the argument without paging through 1300 lines of
normative spec. It folds in material from `PQF-SPEC-v1.md` §8,
`PQF-DESIGN-RATIONALE-v1.md` §8, and the IETF draft's Security
Considerations section, and is cite-able from the I-D.

---

## 1. Adversary model and trust boundary

PQF defends a file against an adversary who can:

- Read, copy, modify, truncate, replay, and reorder the ciphertext
  bytes at rest in transit between the writer and the reader.
- Observe arbitrary metadata around the file (size, time of arrival,
  envelope file system, etc.).
- In the harvest-now-decrypt-later case, archive the ciphertext for
  decades and run a future cryptographically-relevant quantum computer
  against it.
- Hold zero, one, or many recipient identities — but not the identity
  the file is authored to decrypt against.

PQF assumes a trusted writer-side environment for the duration of
encryption (CSPRNG-quality randomness, uncompromised secret memory) and
a trusted reader-side environment for the duration of decryption.
PQF does not defend the *endpoints*; it defends the *file*.

## 2. Assumed primitive properties

PQF's security argument is conditional on the following standardized
assumptions. None of these are PQF's to prove. If any is broken in the
underlying library, PQF's corresponding property fails.

| Primitive | Property assumed | Reference |
|---|---|---|
| X25519 | DH-CKS hardness | RFC 7748 |
| ML-KEM-768 | IND-CCA2 | FIPS 203 (Category 3) |
| X-Wing combiner | IND-CCA in ROM and QROM, given the above | draft-connolly-cfrg-xwing-kem; Barbosa, Boudgoust, Bouvier, Damgård, Kaledin, Pointcheval, Renes 2024 |
| Ed25519 | EUF-CMA | RFC 8032 |
| ML-DSA-87 | sUF-CMA | FIPS 204 (Category 5) |
| AES-256-GCM | IND-CCA2 and INT-CTXT in the per-(key, IV) sense | NIST SP 800-38D |
| SHA-256, SHA-3-256 | preimage / collision / second-preimage resistance at standard levels | FIPS 180-4, FIPS 202 |
| HKDF-SHA-256 | strong pseudorandom expansion from a uniform 256-bit IKM | RFC 5869 |
| Deterministic CBOR (RFC 8949 §4.2.2) | injective encoding: distinct logical structures cannot map to the same byte sequence | RFC 8949 |
| Host CSPRNG | unpredictable to the adversary at encryption time | platform-dependent |

Implementations MUST use library implementations that satisfy these
properties. The reference .NET implementation uses the BCL native ML-KEM
and ML-DSA on .NET 10 (platform-backed); the Rust reader/writer use the
RustCrypto `ml-kem`, `ml-dsa`, `x25519-dalek`, and `aes-gcm` crates.
Constant-time posture is inherited from the library; see §6 below.

## 3. Claimed file-level guarantees

Given the assumptions in §2, PQF v1 0.6 claims the following.

### 3.1 Confidentiality (always)

For a recipient *R* who does not hold a target recipient's identity, the
file's plaintext is indistinguishable from random to *R*. This holds
under the hybrid disjunction: it remains true if **either** X25519's
classical hardness **or** ML-KEM-768's post-quantum CCA security is
preserved.

### 3.2 Integrity (always)

Any single-byte modification of the chunk stream, any reordering of
chunks, any truncation, any extension, any modification of the footer,
and any tampering with `wrapped_dek`, `pqc_ct`, or `classical_epk` in
any recipient block, is detected at decryption time by AEAD tag failure
or footer-count mismatch. There is no recovery path.

### 3.3 Authenticity (signed files only)

For a file with a `signer` block, both Ed25519 and ML-DSA-87
signatures must verify on both signed messages (the header signature
and the file signature). Either failure causes refusal. The hybrid
property carries to authenticity: a forger needs to break **both**
Ed25519 **and** ML-DSA-87 to produce an accepted forgery.

### 3.4 Cross-recipient isolation (always)

A KEK derived for recipient *i* cannot decrypt recipient *j*'s DEK
wrap. This holds via two independent mechanisms:

1. The X-Wing combiner binds the recipient's long-term X25519 public
   key `pk_X` into the KDF input, so each recipient's KEK is
   intrinsically tied to their own key.
2. The DEK-wrap AEAD includes `recipient_index` in its AAD, so even if
   two recipient slots somehow derived the same KEK (they cannot under
   X-Wing), the wrapped-DEK tags would mismatch on the wrong slot.

### 3.5 Cross-file isolation (always)

A KEK derived for one file cannot decrypt any other file's DEK wrap.
This holds via the DEK-wrap AEAD's `file_id` AAD field. Even if an
attacker could replay a recipient block from file A into file B, the
AAD mismatch would refuse the DEK unwrap.

### 3.6 Downgrade resistance within v1 (always)

The `alg` map is covered by the header signature when present, and is
always verified against exact-match string values for each of `aead`,
`combiner`, `kdf`, `kem`, and `sig`. Any deviation refuses the file at
parse. Algorithm agility is by format-version bump, not by negotiation.

### 3.7 Weak deniability (always; see §5.2)

ML-KEM's implicit-rejection property plus PQF's constant-time
recipient trial means that an observer who does not hold any
recipient's identity cannot distinguish, from observation of a
decryption attempt's failure, whether the attempting party was a
recipient or not. This is a **weak** guarantee — strictly weaker than
the deniability of a protocol designed for it (OTR, Signal). The spec
deliberately names it (§8.8) so callers neither rely on it nor
misunderstand it.

## 4. Construction-by-construction argument

### 4.1 KEM combiner

The KEK is derived per recipient as:

```
KEK = SHA3-256( ss_M || ss_X || ct_X || pk_X || XWING_LABEL )
```

This is the construction defined and analyzed in
draft-connolly-cfrg-xwing-kem, with IND-CCA proofs in ROM and QROM. PQF
inherits the proof unchanged for this step. The PQF-specific glue (per
§4.2) is at the next layer.

**Why this matters relative to PQF 0.5.x:** the earlier in-house
`pqf1-bind-extract-v1` HKDF combiner was a PQF-author construction
without external security analysis. The 0.6 cutover to X-Wing
deliberately replaces an unproven construction with a proven one. The
0.5 combiner is gone; readers MUST refuse files that declare it.

### 4.2 Per-recipient and per-file binding via AEAD AAD

X-Wing's combiner has no slot for the file instance or the recipient
slot. PQF binds those at the next layer:

```
wrapped_dek_aad = file_id (16 bytes) || recipient_index (uint32 BE)
```

The argument: the AEAD-AAD binding step preserves cross-recipient and
cross-file isolation because AES-256-GCM's INT-CTXT property
guarantees that ciphertexts with mismatched AADs cannot be made to
verify. The reduction is: an adversary who could unwrap a DEK with the
wrong (file_id, recipient_index) AAD would yield an AES-GCM forgery,
contradicting INT-CTXT under SP 800-38D.

**Status:** this step is straightforward but has not been independently
reviewed. See §5.1.

### 4.3 Per-chunk AEAD

For chunk *i*:

```
chunk_key   = HKDF-Expand(DEK, "PQF1-chunk-v1" || i (8B BE), L=32)
chunk_nonce = 12 bytes, all zero
aad         = file_id (16B) || i (8B BE) || is_final (1B: 0x00 or 0x01)
ciphertext  = AES-256-GCM-Encrypt(chunk_key, chunk_nonce, plaintext_i, aad)
```

The argument: NIST SP 800-38D §8.2 permits any deterministic IV
construction subject to (key, IV) uniqueness. PQF satisfies that by
making the key per-chunk-unique (per-chunk HKDF expansion of the DEK)
rather than the IV. Three invariants must hold for the argument; all
are spec-mandated:

1. DEK freshness per file (single random 256-bit value, never reused).
2. Chunk indices assigned monotonically `0, 1, …, n-1` with no gaps or
   repetition.
3. Single-producer writer; no concurrent encryptors on the same DEK.

Truncation, chunk substitution, chunk reordering, and final-chunk
spoofing are detected by the per-chunk AAD (including `is_final`) plus
the footer integrity check (§4.5).

**Status:** the construction is standard but the specific
HKDF-expand-from-DEK + zero-nonce + is_final-in-AAD composition has not
been independently reviewed.

### 4.4 Hybrid signature composition (signed files only)

Both signatures (header and file) cover their messages via the same
hybrid scheme:

```
hybrid_sig = ed25519_sig(64 bytes) || mldsa_sig(4627 bytes)
```

The signed messages are domain-separated:

- header_sig_message = `"PQF1-header-sig-v1"` || header_bytes
- file_sig_message = `"PQF1-file-sig-v1"` || file_id || sha256(chunk_bytes) || footer

The argument: the hybrid disjunction is preserved trivially by AND-
combining (both halves must verify). Domain-separation prefixes ensure
the two signed messages can never collide regardless of header content
or chunk hash.

**Status:** the AND-of-EUF-CMA composition is standard but has not
been independently reviewed for this construction; in particular, there
is no formal analysis of using the same hybrid keypair for both
signature messages — though the disjoint domain prefixes are intended
to close any such concern by construction.

### 4.5 Footer integrity

The 20-byte footer (`"PQFE"` || chunk_count u64 BE || plaintext_bytes
u64 BE) is covered by the file signature when present.

**On unsigned files**, the footer is protected only by:
- Structural parser checks (magic match, count vs observed-chunks
  match).
- The implicit consistency check from per-chunk AAD.

An adversary who cannot break AEAD cannot forge a footer that matches
an existing chunk stream, so the practical exposure on unsigned files
is denial of service (parser refuses), not silent acceptance of a
tampered length. Whether this should be tightened in v1.1 by
AEAD-binding the footer is rationale §11 question #7 — an open
question solicited for reviewer input.

## 5. Known unanalyzed compositions

These are claims PQF asserts but cannot point to formal external
analysis for. They are flagged here, in `REVIEW-STATUS.md`, and in
`PQF-DESIGN-RATIONALE-v1.md` §11.

### 5.1 The AAD-binding step (§4.2)

The argument is straightforward — INT-CTXT of AES-GCM under correct
key derivation — but PQF has not had a cryptographer independently
work through the reduction in the multi-recipient archival setting.
This is the highest-priority gap for review.

### 5.2 The strength bound on the weak-deniability claim (§3.7)

The claim is bounded carefully in §8.8, but the bound has not been
formally argued. Specifically: does the constant-time recipient trial
plus implicit rejection actually achieve indistinguishability against
an adversary who can choose the ciphertext, or only against a passive
observer? The spec language is conservative; a tighter or looser bound
may be provable.

### 5.3 The per-chunk construction under partial-write / truncation /
recovery (§4.3)

The construction is correct under the three spec invariants. The spec
specifies refusal semantics on truncation. What has not been examined:
behavior under adversarial partial-write that produces *valid-looking*
prefixes — does the reader's refusal path actually fire at every such
prefix? The differential test suite exercises some of this; a
systematic adversarial fuzzer has not been pointed at it.

### 5.4 Constant-time recipient trial as actually implemented

The .NET and Rust references iterate every recipient block regardless
of match. Whether the *instruction stream* is timing-independent
depends on the library implementations of ML-KEM decap and the AEAD
verify primitive, which PQF inherits. No on-machine timing measurement
has been performed; this is a published open question for v1.1.

## 6. Adversary capabilities explicitly out of scope

| Capability | Why out of scope |
|---|---|
| Traffic analysis on file size | Padding is a separate layer with its own tradeoffs; PQF deliberately doesn't pad. |
| Recipient anonymity vs metadata correlation | Recipient public keys, count, and ordering are visible by design. |
| Sender authenticity on unsigned files | Anyone with the recipient's public key can produce an unsigned file. Signature is opt-in for a reason. |
| Side channels in primitive implementations | PQF specifies constructions; the library provides constant-time primitives or it doesn't. |
| Compromised host CSPRNG | If DEK / file_id / ephemeral keys are predictable, confidentiality is gone — but that's true of every system. |
| Endpoint compromise | If the attacker holds a recipient identity, they can decrypt; PQF does not defend stolen keys. |
| Malicious signer | A signature proves "this keypair signed these bytes." It does not prove content truth, intent, or freshness. |
| Forward secrecy in the messaging sense | PQF is a static-file format. Long-term keys decrypt forever. |

## 7. Operational obligations for implementations

The arguments in §4 hold only if implementations meet these
spec-mandated obligations:

- **CSPRNG-sourced DEK, file_id, ephemeral X25519 keys, and any
  random fields in the header.** PQF cannot detect a weak RNG; if
  it's broken, confidentiality is broken.
- **Deterministic CBOR enforcement at parse**, not just at
  production. See spec §2.5 — implementers MUST verify that the
  CBOR library either enforces determinism natively or re-encode
  and byte-compare.
- **Constant-time recipient trial**: iterate every recipient block
  regardless of match. The AEAD tag is the sole signal of a match.
- **Fail-closed on every refusal class** enumerated in spec §8.4.
  No "best effort," no logged-and-continued, no fallback.
- **Streaming Mode failure signaling**: if any post-hoc check fails,
  the failure MUST be signaled to the consumer in a way that
  cannot be silently swallowed. "Logged it" is non-conforming.
- **Memory hygiene for secret material**: DEK, KEK, derived chunk
  keys, and decap shared secrets should be zeroized when no longer
  needed. The spec does not impose specific platform mechanisms.

## 8. References

- RFC 7748 — X25519
- RFC 8032 — Ed25519
- FIPS 203 — ML-KEM
- FIPS 204 — ML-DSA
- NIST SP 800-38D — AES-GCM
- RFC 5869 — HKDF
- RFC 8949 — CBOR (§4.2.2 — deterministic encoding)
- draft-connolly-cfrg-xwing-kem — X-Wing combiner
- Barbosa, Boudgoust, Bouvier, Damgård, Kaledin, Pointcheval, Renes
  (2024) — X-Wing IND-CCA proofs in ROM and QROM
- `PQF-SPEC-v1.md` §8 — normative Security Considerations
- `PQF-DESIGN-RATIONALE-v1.md` §8, §11 — why each decision; open
  questions
- `spec/external-review/REVIEW-STATUS.md` — what has and has not been
  reviewed externally
