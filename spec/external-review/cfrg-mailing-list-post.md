# CFRG mailing-list post — draft

**Status:** unsent. This is a draft for review before sending to
`cfrg@irtf.org`. Read it, edit it, send when ready.

**Suggested subject line:**

> [Review request] PQF: hybrid post-quantum file format using X-Wing — open for cryptographic review

---

To: cfrg@irtf.org
Subject: [Review request] PQF: hybrid post-quantum file format using X-Wing — open for cryptographic review

Hello CFRG,

I'm requesting review of PQF (Post-Quantum File), a hybrid PQ
file-encryption format aimed at the harvest-now-decrypt-later threat
model for long-term archival. It is the equivalent of `age` or
PKCS #7 enveloped data, but hybrid-PQ by default at the format level.

PQF v1 uses:

- **X-Wing** (X25519 + ML-KEM-768) as the hybrid KEM combiner, per
  draft-connolly-cfrg-xwing-kem.
- **Ed25519 + ML-DSA-87** as the optional hybrid signature (4691 bytes
  fixed, classical || PQ concatenation).
- **AES-256-GCM** chunked, with per-chunk-rekeyed HKDF, fixed zero
  nonce, and `is_final` bound into the per-chunk AAD.
- **Deterministic CBOR** (RFC 8949 §4.2.2) for the header, enforced at
  parse (not just produced).

What I'd specifically value review on:

1. **The PQF-specific glue around X-Wing.** X-Wing's combiner has no
   slot for per-file or per-recipient binding. PQF binds those at the
   DEK-wrap AEAD layer instead:
   `wrapped_dek_aad = file_id (16) || recipient_index (uint32 BE)`.
   Is this composition sound for the multi-recipient archival case?
2. **Per-chunk AEAD construction.** Per-chunk rekey + zero nonce +
   `is_final` AAD bit. Conforming under SP 800-38D §8.2 if DEK is
   fresh, indices are monotonic, and the writer is single-producer
   — all REQUIRED by the spec. Are there nonce-reuse or
   truncation attack surfaces I haven't accounted for?
3. **File-signature coverage:** `file_id || sha256(chunks) || footer`.
   Does this composition cover the whole "what the file says it is"
   in one signature without giving up properties I should preserve?
4. **ML-KEM implicit-rejection in the recipient-trial loop**, and the
   bounded "weak deniability" claim built on it (spec §8.8). Is the
   claim correctly scoped?
5. **The constant-time recipient-trial requirement.** Is the spec's
   prose implementable as written, or does it need tightening to
   prevent timing leaks about which recipient slot matched?

Independent implementations exist and produce byte-identical output:
a .NET writer/reader (BouncyCastle), a Rust reader and writer
(ml-kem 0.3, ml-dsa 0.1, x25519-dalek 2.0, aes-gcm 0.10), a Python
binding via maturin, and a WASM bundle. Cross-implementation
conformance is part of CI (Rust reader against .NET vectors, 50
random round-trips, and a replay of the published X-Wing draft KAT).

Documents (under MIT license):

- 3-page reviewer overview:
  https://github.com/systemslibrarian/PostQuantum.FileFormat/blob/main/spec/PQF-OVERVIEW.md
- Normative spec (1300+ lines):
  https://github.com/systemslibrarian/PostQuantum.FileFormat/blob/main/spec/PQF-SPEC-v1.md
- Design rationale, including §10 "what reviewers should focus on" and
  §11 "open questions":
  https://github.com/systemslibrarian/PostQuantum.FileFormat/blob/main/spec/PQF-DESIGN-RATIONALE-v1.md
- IETF Internet-Draft (not yet submitted):
  https://github.com/systemslibrarian/PostQuantum.FileFormat/blob/main/spec/ietf/draft-clark-pqf-00.md
- Conformance vectors:
  https://github.com/systemslibrarian/PostQuantum.FileFormat/tree/main/test-vectors/v1

The status is explicitly DRAFT / EXPERIMENTAL — no external
cryptographic review has happened to date, only LLM-assisted review
during drafting (which is acknowledged in the rationale doc, not hidden).
The point of this email is to get real review before the format
freezes for v1.0.

Pointers, objections, or "this part is wrong" — all welcomed. Happy to
discuss on-list or off-list, whichever the group prefers.

Thanks,
Paul Clark
<paul@systemslibrarian.dev>
https://github.com/systemslibrarian/PostQuantum.FileFormat

---

## Sending notes (delete before sending)

- Replace `[link to ...]` placeholders with real URLs to the files on
  `main` (or a tagged release commit). GitHub blob URLs are fine.
- CFRG list etiquette: plain text, no HTML, no attachments. One topic
  per thread. Don't cross-post to other IETF lists for this first
  thread.
- The list is public and archived. Anything you send is permanent.
- Expect days-to-weeks for substantive responses; follow up once after
  ~3 weeks if quiet.
- Sign up at https://www.irtf.org/mailman/listinfo/cfrg first if not
  already subscribed; non-subscriber posts are moderated.
