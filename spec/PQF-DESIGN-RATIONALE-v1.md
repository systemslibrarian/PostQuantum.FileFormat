# PQF Design Rationale — Companion to PQF-SPEC-v1

**Status:** DRAFT / EXPERIMENTAL companion to PQF-SPEC-v1 v0.3.1
**Document version:** 0.1.0 (2026-04-21)
**Author:** Paul Clark <paul@systemslibrarian.dev>
**License:** MIT

> *"So whether you eat or drink or whatever you do, do it all for the glory of God."* — 1 Corinthians 10:31

---

## Purpose of this document

The PQF specification (`PQF-SPEC-v1.md`) tells you *what* the format is. This
document tells you *why*. It exists so that reviewers — especially
cryptographers who see the spec without context — can understand the
engineering judgments behind each decision without having to infer them from
MUST/MUST NOT language.

This document is non-normative. If this rationale and the spec ever conflict,
the spec wins.

---

## 1. Why PQF exists

### 1.1 The gap

As of April 2026, post-quantum cryptographic primitives are standardized
(FIPS 203, 204, 205) and available in mainstream toolchains (.NET 10, OpenSSL
3.5+, BouncyCastle). Hybrid transit-layer protocols are shipping:
X25519MLKEM768 is live in Chrome, Edge, Firefox. SSH has PQ-hybrid key
exchange. The IETF is deep into hybrid-KEM combiner drafts.

File-at-rest protection has lagged. The closest thing to a modern standard
is `age`, which has experimental PQ plugins but was not designed
hybrid-by-default. OpenPGP's PQ story is evolving but remains tied to the
complexity of the broader OpenPGP ecosystem. Enterprise tools (CMS, PKCS #7)
are heavy and not aimed at the "I have a file I want to encrypt for a few
people" use case.

PQF is meant to fill that gap: a small, opinionated, hybrid-PQ-by-default
file container for long-term archival and sharing.

### 1.2 The harvest-now-decrypt-later threat

The motivating threat model is not "quantum computers exist today" but "an
adversary who stores ciphertext today may decrypt it decades from now." For
files that must remain confidential for 20, 30, or 50 years — medical
records, legal archives, classified research, library special collections,
sealed court records — classical encryption alone is insufficient.

Hybrid construction addresses this by ensuring confidentiality holds if
*either* the classical primitive or the post-quantum primitive remains
unbroken. A complete break of both is required to violate confidentiality.

### 1.3 Why not just use age with PQ plugins

Three reasons:

1. **Hybrid by default, not by plugin.** age's PQ support depends on
   plugins, which are optional. A file encrypted with age today does not
   guarantee hybrid protection; it guarantees whatever the writer's plugin
   chose. For a format intended to survive decades, defaulting to hybrid at
   the format level rather than the tool level is the safer posture.

2. **Explicit multi-recipient with strong isolation.** age handles
   multi-recipient well, but PQF's per-recipient KEK derivation with
   `recipient_index` in the HKDF-Extract salt provides cryptographic
   isolation between recipients that is stronger than simple per-recipient
   key wrapping.

3. **Optional hybrid signatures integrated into the format.** age does not
   sign; signing is a separate tool (minisign, etc.) in the age ecosystem.
   PQF integrates hybrid signatures as a first-class format feature,
   including signature coverage of the footer and chunk hash — so
   truncation, extension, and recipient substitution are all cryptographically
   detectable in one pass.

This is not a claim that PQF is better than age. age is a deliberately
ultra-minimal tool with excellent design properties. PQF is a different
tradeoff: slightly more complex, more integrated, aimed specifically at
archival and multi-party scenarios where hybrid protection and optional
signing matter from day one.

---

## 2. Primitive choices

### 2.1 Why X25519 + ML-KEM-1024 (Category 5) rather than ML-KEM-768 (Category 3)

ML-KEM-768 is already above the common classical baseline (roughly equivalent
to AES-192 security). ML-KEM-1024 is roughly equivalent to AES-256.

For a file format intended for archival confidentiality on decade-plus
horizons, the incremental cost of Category 5 is trivial:

- Public key: 1568 bytes vs 1184 bytes (difference: 384 bytes)
- Ciphertext: 1568 bytes vs 1088 bytes (difference: 480 bytes)
- Slightly slower encap/decap, not measurably so on modern hardware

The benefit is a larger security margin against future cryptanalytic
progress on lattice problems. Lattice-based cryptography is younger than
RSA or ECC; the analytic understanding continues to mature. Choosing the
more conservative parameter set for an archival format matches the intent
of the tool.

For files intended for transient confidentiality (TLS-like use cases),
Category 3 would be appropriate. PQF is not that tool.

### 2.2 Why Ed25519 + ML-DSA-87

Same reasoning applied to signatures. ML-DSA-87 signatures are ~4627 bytes,
which is large in absolute terms but negligible compared to a typical
encrypted file payload. Key sizes follow the same pattern — 2592 bytes for
the public key is unpleasant for human exchange (addressed by the
fingerprint format in §7.3 of the spec) but workable programmatically.

SLH-DSA (FIPS 205, hash-based) was considered and rejected for the default
signature. Hash-based signatures are attractive for long-term security
because they rely only on hash function assumptions, but SLH-DSA signatures
are 17,088–49,856 bytes depending on parameter set. That's a significant
per-file overhead for a file format where most files will be signed. ML-DSA
offers a better size/security tradeoff for this use case. A future PQF
version may add SLH-DSA as an alternative signer for callers who prefer
hash-based security.

### 2.3 Why AES-256-GCM for the payload

AES-256-GCM is:

- Standardized (NIST SP 800-38D)
- Hardware-accelerated on essentially every modern CPU (AES-NI, ARMv8 Crypto
  Extensions)
- Widely audited
- Appropriate for the chunked-payload pattern

ChaCha20-Poly1305 was considered as an alternative. It has some advantages
(no hardware-side-channel concerns, better performance on platforms without
AES acceleration). But for file-at-rest use cases the caller is almost
always on a server or desktop with AES-NI, and AES-GCM's standardization
weight is higher. The choice is a judgment call; ChaCha20-Poly1305 would
not have been wrong.

### 2.4 Why HKDF-SHA-256 for the combiner

HKDF (RFC 5869) is the standard construction for deriving multiple keys from
a shared secret. SHA-256 is universally available and appropriate for
32-byte shared secrets (X25519 and ML-KEM-1024 both produce 32-byte
secrets).

SHA-384 or SHA-512 would offer more collision resistance but add no
meaningful security for keys derived from 32-byte inputs. SHA-3 would also
work; SHA-2 was chosen for ubiquity.

### 2.5 Why "concatenate-then-extract" for the combiner

The spec combiner is:

```
combined_ss = HKDF-Extract(
    salt = "PQF1-combiner-v1" || file_id || recipient_index,
    ikm  = x25519_shared_secret || mlkem_shared_secret
)
```

This follows the **concatenate-then-extract** pattern of
`draft-ounsworth-cfrg-kem-combiners`, with the binding deviations noted
below. Several alternatives were considered:

- **XOR the secrets:** Too weak; cancels under certain conditions.
- **Hash the concatenation directly:** Works, but HKDF's Extract-then-Expand
  structure is the IETF-preferred pattern.
- **Dual-PRF constructions:** More complex, no clear security benefit for
  this specific use case.

Binding `file_id` and `recipient_index` into the salt provides early domain
separation. Even if X25519 or ML-KEM outputs were somehow reused across
files or recipients (which would itself indicate a primitive break), the
combined secrets diverge. This is defense-in-depth at a place where the
cost is zero.

#### How this deviates from the IETF/X-Wing combiners

PQF's combiner is **not** wire- or transcript-equivalent to
`draft-ounsworth-cfrg-kem-combiners` or to the X-Wing KEM, and reviewers
should not assume the security proofs of those constructions transfer
unchanged. The specific differences are:

1. **No ciphertext/public-key binding in the KDF input.** X-Wing and the
   "KitchenSink"-style profiles of the CFRG combiner feed the ML-KEM
   ciphertext (and in X-Wing, a fixed label plus the X25519 ephemeral and
   ML-KEM public-key material) into the hash transcript, which is what
   gives those constructions their ciphertext-binding / MAL-BIND
   properties. PQF feeds **only** the two raw shared secrets
   (`ss_x25519 || ss_mlkem`) as IKM. The ML-KEM ciphertext and the X25519
   ephemeral public key are *not* part of the combiner transcript.
2. **Binding is relocated, not omitted.** PQF instead binds context
   through (a) the `file_id`-and-`recipient_index` salt at Extract time,
   and (b) the AEAD AAD (`file_id || chunk_index || is_final`) at
   encryption time. The recipient block as a whole — including the
   ML-KEM ciphertext — is covered by the header integrity check
   (deterministic-CBOR re-encoding, and the file signature when signed).
   So an attacker cannot swap a recipient's ciphertext undetected on a
   signed file, but the *combiner output itself* is not a commitment to
   the ciphertext the way X-Wing's is.
3. **Consequence.** PQF does not claim the formal MAL-BIND-K-CT /
   LEAK-BIND-K-PK binding notions that X-Wing targets. It claims IND-CCA
   confidentiality of the DEK under the standard hybrid-KEM assumption
   (security holds if *either* X25519 *or* ML-KEM is unbroken) plus
   integrity of the recipient block via the header check. Achieving
   X-Wing parity (folding the ML-KEM ciphertext and public-key material
   into the combiner transcript) is tracked as a v1.1 roadmap item; see
      §11.9.
specified above*, not the X-Wing variant.

---

## 3. Encoding choices

### 3.1 Why CBOR (not JSON, not a custom TLV)

The original draft used canonical JSON. Three rounds of external review
converged on the same conclusion: canonical JSON for signature-bearing
formats is a historical source of interop bugs (JWS is the cautionary tale).
Deterministic CBOR (RFC 8949 §4.2.2) eliminates that bug class by
construction — a given data structure has exactly one valid deterministic
CBOR encoding.

Custom TLV was considered and rejected. Designing a new binary format for
the header means implementing parsers from scratch in every language,
writing a grammar, and hand-rolling conformance checks. CBOR is a
standardized, widely-implemented format; the only cost is requiring
implementers to choose a CBOR library that supports (or can be made to
support) deterministic encoding.

JSON was the more comfortable default. The decision to switch was an honest
acknowledgment that the header is mostly binary blobs (base64-encoded ML-KEM
data), and that "human readable JSON" was largely illusion. CBOR reduces
header size by ~30% as a side benefit of dropping the base64 layer.

### 3.2 Why enforce deterministic CBOR so strictly

Non-deterministic CBOR encoding would allow an attacker or a sloppy
implementation to produce a file whose header parses successfully but whose
signature verification depends on exact byte-level reproducibility of the
header. Permissive CBOR parsing (accepting non-canonical encoding and
normalizing silently) opens the same bug surface that plagued canonical
JSON.

The spec's §2.5 requirement that readers verify determinism — either via a
parser that enforces it natively or via parse-then-re-encode-and-compare — is
the only way to close that loophole portably.

### 3.3 Why JSON for test vector manifests but CBOR for the format itself

Test vector manifests describe inputs and expected outputs; they are not
security-critical artifacts and are read by humans and tools that want to
understand what a vector is. JSON is fine here. The asymmetry is
deliberate: the format needs determinism for security; the test harness
needs readability for debugging.

### 3.4 Why the header is length-prefixed even though CBOR is self-delimiting

Defensive parsing. A reader should be able to check that the declared
header length is sane (≤ 1 MiB) before handing bytes to a CBOR parser. This
is defense against CBOR parser bugs — if a parser has an unbounded-allocation
bug triggered by crafted input, the length prefix caps the damage.

The 1 MiB limit was chosen to be comfortable for 100-recipient files (about
180 KiB of header) with substantial headroom, while preventing DoS via
header inflation.

---

## 4. Structural choices

### 4.1 Why multi-recipient at the format level

age gets this right: encrypting a file for three people should produce one
file, not three. PQF follows the same pattern — a single DEK encrypts the
payload, and the DEK is wrapped once per recipient using the recipient's
hybrid public key.

This is not just convenience. If each recipient got a separate file, rotating
the plaintext (replacing the file with a new version) would require the
sender to maintain a list of recipients and re-encrypt N times. With
multi-recipient, the sender encrypts once.

### 4.2 Why per-recipient KEK with `recipient_index` in the salt

Two reasons:

1. **Isolation.** A compromise of one recipient's identity should not assist
   attacks on other recipients' wrapped DEKs. Binding `recipient_index` into
   the HKDF-Extract salt ensures each recipient's KEK is independently
   derived even if the underlying KEM outputs happened to collide.

2. **No cross-file linkage.** Two files encrypted to the same recipient
   produce two different KEKs because `file_id` is also in the salt. An
   attacker who somehow recovers one file's KEK learns nothing about the
   other file's KEK.

### 4.3 Why chunked AEAD rather than whole-file AEAD

Whole-file AEAD doesn't stream — the reader must buffer the entire file
before verifying the tag. For a format meant to handle files of arbitrary
size (backups, video, database dumps), this is unacceptable.

Chunking allows bounded-memory streaming encryption and decryption. The
tradeoff is that the format now has to handle chunk ordering, truncation,
and chunk-boundary attacks. The `is_final` flag bound into AAD, the
per-chunk key derivation, and the footer's chunk count all exist to close
those attack surfaces.

### 4.4 Why `is_final` in AAD instead of just at the end of the file

Without `is_final` in the AAD, an attacker who truncates the file to end
early would produce a file where the last valid chunk still verifies. The
reader would process chunks until running out of bytes and would not be
able to cryptographically distinguish "end of file" from "truncation."

Binding `is_final` into the AAD means the final chunk is cryptographically
distinguished from non-final chunks. Any truncation attack is detected at
chunk-decryption time.

### 4.5 Why a structured footer rather than just a magic marker

An earlier version of the spec had the footer as a 4-byte magic `PQFE`
delimiter only. Review feedback converged on making the footer do more work:

- `chunk_count` and `plaintext_byte_count` provide redundant structural
  validation independent of AEAD tags and signatures
- The footer is covered by the file signature, binding these structural
  claims to the signer
- Debugging and forensics benefit: `pqf inspect` can show file structure
  without decrypting anything

The 20-byte footer was designed to be minimal while earning its place. Four
bytes magic, eight bytes chunk count, eight bytes plaintext bytes. No
padding, no optional fields.

### 4.6 Why the file signature covers `file_id || sha256(chunks) || footer`

This composition ensures the signer's attestation covers:

- The file identity (`file_id`, which is also the AAD for every AEAD
  operation) — prevents replay between files
- The payload contents (via SHA-256 of the on-disk chunk bytes)
- The structural claims (via the footer bytes exactly as written)

A signature that covered only `sha256(chunks)` would allow an attacker to
swap the footer without detection. A signature that covered only the footer
would allow payload tampering. Covering both with `file_id` prepended ties
the attestation to the specific file instance.

An alternative was considered: signing a Merkle root over chunks, which
would allow streaming signature verification. This was deferred to v2
because (a) it adds complexity, (b) the current construction works, and
(c) authenticated-mode processing requires buffering anyway. The Merkle
variant is a legitimate v2 feature but not a v1 requirement.

---

## 5. Processing mode design

### 5.1 Why two modes

Streaming is a real requirement for large files. But releasing plaintext
before signature verification is a real security concern. A single mode
would force everyone to choose one or the other globally; two modes let the
caller choose based on the specific use case.

Authenticated Mode is mandatory for conforming implementations because:

- It is the safer default
- Applications that don't explicitly need streaming should get verification
  before data
- Making it optional would mean implementations could skip it and still
  claim conformance

Streaming Mode is optional because:

- Not every application needs it
- Implementing it correctly (with honest post-hoc failure signaling)
  requires more care
- An implementation that only supports Authenticated Mode is still useful

### 5.2 Why the failure-signaling requirement for Streaming Mode is so strict

The subtle danger in streaming is that plaintext has already left the
library. If the post-hoc signature check fails and the library only logs a
warning, the application may act on unauthenticated data believing it was
verified.

The spec's requirement that failure signaling be "impossible for the caller
to overlook through ordinary use" is deliberately strong language. Log-only
reporting is explicitly non-conforming. Acceptable mechanisms are: thrown
exceptions that propagate, non-zero return codes that the compiler or
language type system forces the caller to handle, or explicit `Result`
types.

This is not overreach. It's recognition that getting this wrong once, in a
widely-deployed library, would undermine the format's credibility.

---

## 6. Key format design

### 6.1 Why three representations

- **Canonical binary** (1601 bytes for encryption keys): the single source
  of truth. All cryptographic operations and fingerprint computations use
  this.
- **PEM-armored**: for human-exchangeable transport. Works in email, chat,
  documentation, file systems.
- **Fingerprint** (32-byte SHA-256 of canonical binary): for human
  verification of key authenticity.

An earlier draft used bech32 as the primary human-exchange format. The
resulting 2570-character single-line string was ergonomically poor. Review
feedback converged on PEM as the correct transport format and fingerprints
as the verification shortcut.

### 6.2 Why the "fingerprints MUST NOT be cryptographic identifiers" rule

Because someone will try. Every system that has a short human-readable
identifier eventually sees it used as a database primary key, a lookup
index, or an authorization token. SSH key fingerprint collisions have been
demonstrated in research; the same applies here.

Stating the rule explicitly in the spec is cheap and forestalls a class of
deployment bugs.

### 6.3 Why PEM instead of a custom armored format

PEM is boring. Every developer has seen it. Every language has a parser.
Every mail client handles it. A custom armored format would be more elegant
in isolation but add adoption friction for zero security benefit.

---

## 7. Extensibility posture

### 7.1 Why v1 rejects unknown fields

An earlier draft allowed unknown top-level fields for "forward
compatibility." Review feedback correctly identified this as a contradiction
with the "versioned and frozen" positioning. You cannot simultaneously
claim strict versioning and permissive parsing.

The resolution: v1 rejects all unknown fields at all levels. Extensions
require a version bump. This is stricter than many specs but appropriate
for a security format — a v1 reader that silently ignores unknown fields
cannot tell whether it is missing security-relevant information.

### 7.2 Why no profile mechanism in v1

A profile mechanism (multiple primitive suites within a single version)
adds complexity and negotiation. v1 uses exactly one primitive suite.
Future versions may introduce profiles if needed; the versioning section
(§10 of the spec) explicitly keeps that option open without committing to
a design now.

---

## 8. Security posture

### 8.1 Why so many things are explicitly out of scope

PQF's §8.2 and §11.2 enumerate what PQF does NOT protect against. This is
deliberate. A spec that claims to solve every problem protects against
nothing reliably.

- Traffic analysis is out of scope because hiding file size would require
  padding, which has its own tradeoffs and is better done at a different
  layer.
- Recipient anonymity is out of scope because strong anonymity against
  metadata analysis would require rethinking the recipient-block design.
- Forward secrecy in the messaging sense is out of scope because PQF is a
  static-file format, not a protocol.

Being honest about what PQF doesn't do makes the spec more trustworthy, not
less.

### 8.2 Why deniability is called out explicitly

ML-KEM's implicit rejection property (decap returns pseudorandom data
rather than failing on malformed ciphertext) plus PQF's constant-time
recipient trial produces a weak deniability property: a party cannot prove
they were NOT a recipient of a given file.

This property is present whether we name it or not. Naming it does two
things:

1. Applications that want to rely on it know what guarantee they actually
   have (weak, not strong).
2. Applications that might misunderstand it know they should not claim
   strong deniability.

The spec is careful not to call PQF a "deniability protocol." It isn't.
The property is a consequence of the primitives, not a design goal.

---

## 9. What was considered and rejected

### 9.1 Password-based recipients (deferred)

age has a `scrypt` recipient type for passphrase-encrypted files. PQF will
likely add something similar in v2. It was deferred from v1 because:

- It requires a careful password hashing choice (Argon2id? scrypt?
  PBKDF2-SHA256 with high iterations?)
- It has different threat model implications than public-key recipients
- Getting it wrong in v1 would be worse than not having it in v1

### 9.2 Hardware token support (deferred)

Standards for ML-KEM / ML-DSA on smartcards and HSMs (PKCS #11, etc.) are
still emerging. Designing hardware support into v1 would either commit to
interfaces that may change, or be so abstract as to be useless. Deferred
until the underlying standards mature.

### 9.3 Compression (rejected)

PQF does not compress. Compression before encryption creates side channels
(CRIME, BREACH) that leak information about plaintext through ciphertext
size. Applications that want compression should compress before handing
data to PQF.

### 9.4 Forward secrecy (out of scope)

PQF is a static-file format. Forward secrecy is a property of protocols
where session keys can be destroyed. For a file sitting on disk,
"forward secrecy" doesn't have the same meaning — the ciphertext exists,
and if the recipient's long-term key is compromised, the file is
decryptable. This is an inherent limitation of at-rest encryption, not a
PQF-specific gap.

### 9.5 Built-in key rotation (deferred to v2)

A "rewrap" operation that re-encrypts a file's DEK to new recipients
without the original sender's keys is a natural v2 feature. It requires
careful design to avoid weakening the signer-authenticity story (the
original signer can no longer attest to the new recipient list).

### 9.6 Merkle-tree signatures (deferred to v2)

Signing a Merkle root over chunks rather than a single hash would enable
streaming signature verification and partial verification of individual
chunks. Deferred because:

- The v1 construction works
- Authenticated mode already requires buffering
- Adding complexity to v1 increases spec surface area without a clear v1
  beneficiary

### 9.7 Certificate formats / PKI integration (out of scope)

PQF keys are raw (with a version byte and simple wire format). Integration
with X.509, PKCS #7, or any certificate ecosystem is intentionally out of
scope. Applications that need certificate-based trust should layer that on
top of PQF, not expect PQF to provide it.

---

## 10. What reviewers should focus on

If you are reviewing PQF with limited time, the highest-value sections to
examine are:

1. **§2.4 combiner construction.** Is the salt binding correct? Does the
   IKM ordering matter? Are there any multi-target attack surfaces?
2. **§6.2 step 9 signature coverage.** Does the composition
   `file_id || sha256(chunks) || footer` cover everything it needs to?
3. **§5.2 per-chunk AEAD construction.** Does the chunk_key derivation +
   zero nonce + AAD composition avoid every nonce-reuse and truncation
   attack?
4. **§6.3 step 7b ML-KEM implicit rejection handling.** Does the spec
   correctly prevent timing leaks about recipient index?
5. **§8.8 deniability claim.** Is the claim bounded correctly? Should it
   say less?

Lower-priority review targets:
- Spec prose clarity
- Test vector coverage
- Library API surface

The cryptographic core is the part where review time has the most impact.

---

## 11. Open questions the author acknowledges

Places where the author is uncertain and would value external input:

1. **Canonical CBOR library support.** Deterministic CBOR encoding is
   specified in RFC 8949 §4.2.2, but not every CBOR library enforces it
   natively. Implementers need to choose libraries carefully. Is the spec's
   "parse or re-encode-and-compare" rule workable in practice across major
   languages?

2. **Hybrid combiner formal treatment.** The combiner follows current IETF
   draft guidance but has no formal security proof for the specific
   assembly. Is the concatenate-then-extract-with-salt construction
   appropriate for this use case, or is there a stronger construction
   that's still simple?

3. **Deniability framing.** The spec's §8.8 claims "weak deniability"
   deliberately. Is this framing correct, or is it either over- or
   under-claiming?

4. **Recipient count scaling.** §6.4 guidance suggests supporting at least
   100 recipients. Is this the right number? Are there use cases where
   thousands of recipients are needed? If so, the constant-time trial
   approach becomes painful and a "recipient hint" mechanism (deferred to
   v2) becomes more important.

5. **Key format longevity.** The canonical binary format embeds the
   current primitive suite. A v2 with different primitives will have a
   different key format. Is this the right call, or should v1 keys have
   been more generic?

6. **Domain separation between header signature and file signature.**
   The same hybrid signing key signs two distinct messages: the
   deterministic CBOR header bytes (header signature, §6.2 step 5) and
   `file_id || sha256(chunks) || footer` (file signature, §6.2 step 9).
   The two messages are structurally distinct and short, so the author
   does not see an obvious cross-protocol path that would let one
   signature be replayed as the other. Even so, prepending an explicit
   domain-separation prefix — e.g. `"PQF1-header-sig-v1"` and
   `"PQF1-file-sig-v1"` — to each message before it reaches the signer
   would close the question by construction. This would be a v1.1
   wire-format change (signature inputs change, but key formats and
   ciphertext layout do not). Should the spec adopt this now, or wait
   for a concrete attack?

7. **Footer integrity on unsigned files.** When a file is signed the
   20-byte footer is covered by the file signature (§6.2 step 9). When
   a file is unsigned the footer is only protected by the parser's
   structural checks: footer magic, `chunk_count` matching the observed
   number of chunks, and `plaintext_bytes` matching the observed
   plaintext length. An attacker who cannot break AEAD cannot forge a
   footer that matches an existing chunk stream, so the practical
   exposure is limited to denial of service (the parser refuses), not
   silent acceptance of a tampered length. A future v1.1 could AEAD-
   bind the footer with a separate per-file key derived from the DEK
   to give unsigned files cryptographic footer integrity. This would
   be a wire-format change; gathering reviewer opinion on whether the
   added complexity is warranted before committing.

8. **Constant-time guarantees of the underlying primitives.** PQF
   specifies the high-level cryptographic constructions but is silent
   on the constant-time / side-channel properties of the KEM, AEAD,
   and signature primitives — those are properties of the implementer's
   chosen library. The .NET reference implementation uses BouncyCastle
   for ML-KEM-1024 and ML-DSA-87, which is managed C# code without
   claimed constant-time guarantees against power, EM, or
   microarchitectural side channels. Should the spec require
   conforming implementations to document the side-channel posture of
   their dependencies, even though it cannot meaningfully require a
   particular posture?

9. **X-Wing / CFRG-combiner parity for ciphertext binding (v1.1
   roadmap).** As detailed in §2.5, PQF's combiner feeds only the two raw
   shared secrets as IKM and relocates context binding to the salt
   (`file_id || recipient_index`) and the AEAD AAD, rather than folding
   the ML-KEM ciphertext and the X25519/ML-KEM public-key material into
   the KDF transcript the way X-Wing and the binding profiles of
   `draft-ounsworth-cfrg-kem-combiners` do. As a result PQF does not
   inherit the formal MAL-BIND-K-CT / LEAK-BIND-K-PK binding notions of
   those constructions; it relies on the header integrity check to make
   recipient-block substitution detectable on signed files. A v1.1
   profile could adopt an X-Wing-equivalent transcript
   (`label || ss_mlkem || ss_x25519 || ct_mlkem || epk_x25519 ||
   pk_mlkem`) to obtain ciphertext binding by construction. This is a
   wire-format change (combiner input changes; key formats and ciphertext
   layout do not). The open question is whether the added binding is
   worth diverging from the deliberately minimal v1 combiner, and whether
   to track upstream X-Wing standardization before committing.

---

## 12. Acknowledgments

The spec was drafted iteratively with AI-assisted review cycles. Review
feedback from Claude, Grok, and ChatGPT during drafting caught design
issues including:

- The unknown-fields extensibility contradiction
- Canonical JSON fragility (leading to the CBOR switch)
- Authenticated vs streaming mode semantics
- CBOR determinism enforcement gaps
- Bech32 ergonomics for long public keys
- Recipient privacy overclaiming

External human cryptographer review has not yet occurred as of the date of
this document. The EXPERIMENTAL label on the spec applies until that review
happens.

---

## Document history

| Version | Date | Notes |
|---|---|---|
| 0.1.0 | 2026-04-21 | Initial rationale document, companion to spec v0.3.1 |
