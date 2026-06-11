# Workshop submission abstract — draft

**Status:** unsent. This is a single 450-word abstract aimed at
**Real World Crypto (RWC)** or **Real-World Post-Quantum Crypto
(RWPQC)**. Both venues accept short-talk / lightning-talk proposals
that are accessible and applied. Pick the venue, adapt the
opening sentence, and submit.

**Venue notes for picking one (delete before submission):**

- **RWC (Real World Crypto)** — annual IACR-affiliated symposium,
  applied-crypto leaning, broad audience. PQF fits as a "deployed
  file-at-rest format using NIST PQ standards" talk. Submission is
  typically a short abstract; talks are ~25 min. Strong reach to
  cryptographers who work on standardization. Best fit if you want
  the broadest cross-section of the applied-crypto community.
- **RWPQC (Real-World Post-Quantum Crypto)** — newer, NIST-affiliated
  workshop explicitly about deploying NIST PQ standards. PQF is
  exactly the kind of artifact RWPQC wants to surface (an
  independent, open-source, hybrid-PQ deployment that's been
  through cross-implementation interop). Best fit if you want
  feedback from the people writing the standards rather than the
  broader community.

- **Not RWC or RWPQC?** This abstract is also adaptable to a USENIX
  Security poster, an IETF presentation slot (CFRG or SAAG), or an
  industry conference. Adjust the framing of the opening sentence
  to suit the venue's audience.

---

## Title

**PQF: a hybrid post-quantum file format using X-Wing for long-term archival**

## Abstract (~450 words)

We present PQF (Post-Quantum File), an open-source file-encryption
format designed for the harvest-now-decrypt-later threat model. PQF
addresses a specific gap in the post-quantum transition: hybrid PQ
transit protocols are widely deployed (X25519MLKEM768 in Chrome, Edge,
Firefox; PQ-hybrid SSH key exchange; multiple IETF drafts in flight),
but file-at-rest formats have lagged. age, GPG, and S/MIME remain
classical-by-default; PQ support is plugin-only or absent. PQF is an
attempt to make hybrid post-quantum confidentiality the *default*, not
an opt-in, at the format level, in a small, fail-closed container that
can be implemented end-to-end in an afternoon.

PQF v1 uses **X-Wing** (X25519 + ML-KEM-768) per
draft-connolly-cfrg-xwing-kem as its hybrid KEM combiner, with IND-CCA
proofs — classical in the ROM and post-quantum in the standard model
(Barbosa et al., 2024). Hybrid
signatures (Ed25519 + ML-DSA-87, concatenated) are optional. The
payload is AES-256-GCM chunked, with per-chunk-rekeyed HKDF, a fixed
zero nonce, and an `is_final` AAD bit that makes truncation an AEAD
verify failure rather than a footer mismatch. The header is
**deterministic CBOR** (RFC 8949 §4.2.2), and the spec REQUIRES that
readers enforce determinism on parse — not merely produce it on
encode. Unknown header fields at any level are refused. The result is
a 1300-line spec, a small reference .NET implementation, and an
independent Rust reader and writer that share no code with the
reference.

We will discuss three design decisions that produced unexpected
follow-on simplifications. **First**, cutting over from a
PQF-author in-house HKDF combiner (`pqf1-bind-extract-v1`) to
standardized X-Wing meant we could inherit a proof rather than ship
one — and pushed per-file and per-recipient binding down to the
DEK-wrap AEAD's AAD (`file_id || recipient_index`), where it
composes more cleanly. **Second**, the per-chunk-rekey + zero-nonce
construction avoided counter-IV bookkeeping and made the
`is_final` bit a natural place to bind truncation defense.
**Third**, requiring deterministic CBOR *enforcement on parse* — a
substantial implementation burden — turned out to eliminate a class
of signed-canonicalization bugs that have historically dogged
file-encryption formats.

PQF is **DRAFT / EXPERIMENTAL**. No external cryptographic review has
happened yet; this submission is partly to invite it. What we have so
far is mechanical interop evidence: cross-implementation conformance
between the .NET writer and Rust reader on every published vector, a
replay of the X-Wing draft KAT against published IETF vectors, and a
reproducible test-vector regeneration pipeline. We would value
feedback on the AAD-binding composition around X-Wing, the per-chunk
AEAD construction's behavior under adversarial truncation, and the
weak-deniability claim built on ML-KEM's implicit rejection.

Spec, rationale, IETF Internet-Draft, and conformance suite under MIT
license at:
**<https://github.com/systemslibrarian/PostQuantum.FileFormat>**

## Speaker

Paul Clark — independent developer; PQF author and editor of the
spec, reference implementation, and IETF Internet-Draft.

## Submission notes (delete before sending)

- Word count of the abstract proper (excluding title, speaker bio,
  these notes): ~450 words. Trim to venue's limit if needed (RWC
  typically asks for ≤500; RWPQC is more flexible).
- The "three design decisions" paragraph is the most adaptable —
  swap one of the three for whatever a venue would find most
  surprising, if you have a sense of audience.
- The honesty about no external review is deliberate. If you'd
  prefer to soften it, change "No external cryptographic review has
  happened yet" to "External cryptographic review is actively
  in progress" *after* the CFRG post has been sent and at least one
  researcher has engaged. Don't soften before that's true.
- Talks at RWC/RWPQC favor demos and design-decision war stories
  over walking the spec section by section. Plan the talk to mirror
  the abstract's structure: gap → choices → unexpected simplifications
  → what reviewers should focus on.
