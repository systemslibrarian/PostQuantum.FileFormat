# Request for cryptographic review — PQF

**What this is.** PQF is an experimental, spec-first hybrid post-quantum file
format for data at rest. It is **not** in production use, makes no
"production-ready" claim, and is explicitly labelled draft/experimental. I am a
solo author looking for an independent cryptographer's eyes on the
construction before it goes anywhere near a v1.0.0 freeze.

**The ask.** A targeted review — even a narrow or critical one — of the four
areas below. I am specifically not asking for a full audit or a stamp of
approval; I want to know where the construction is wrong, underspecified, or
resting on an assumption that doesn't hold.

## The construction in one paragraph

X25519 + ML-KEM-1024 encapsulation, combined through HKDF-SHA-256 into a
per-recipient key-encryption key that wraps a random data key; payload is
chunked AES-256-GCM with a unique HKDF-derived key per chunk and a fixed
all-zero nonce; optional hybrid signatures are Ed25519 + ML-DSA-87 (both must
verify). Header is deterministic CBOR (RFC 8949 §4.2.2), fail-closed, with a
closed schema. Full normative spec: `spec/PQF-SPEC-v1.md` (draft 0.5).

## The four review targets

1. **The KEM combiner** (`spec/PQF-SPEC-v1.md` §2.4, rationale §2.5). As of
   draft 0.5 it is "bind-extract": `HKDF-Extract(salt = label || file_id ||
   recipient_index, ikm = ss_x25519 || ss_mlkem || classical_epk || pqc_ct)`.
   It deliberately is **not** byte-equivalent to X-Wing (HKDF-SHA-256, and it
   folds `pqc_ct` explicitly though ML-KEM's FO already binds it). Does the
   stated claim — IND-CCA confidentiality of the DEK if *either* primitive
   holds — actually follow? Is the explicit transcript binding correct, or is
   it doing nothing / introducing a new problem?

2. **Unsigned whole-payload erasure-to-empty.** An attacker can delete every
   chunk from an *unsigned* file and rewrite the unauthenticated footer to
   `0/0`, yielding a valid empty file. Documented as an accepted tradeoff
   (unsigned ≡ no authenticity). Is that disposition defensible, or does it
   need a fix even for unsigned files?

3. **Signature construction.** Two signatures from one hybrid key over
   domain-separated messages (`PQF1-header-sig-v1` / `PQF1-file-sig-v1`); file
   signature covers `file_id || sha256(chunks) || footer`. Any cross-protocol
   or coverage gap?

4. **Streaming post-hoc verification.** Streaming mode releases plaintext
   before the final signature/footer check, signalling failure via an
   un-ignorable result. Is the contract sound, or is it a foot-gun even as
   specified?

## What's already been done (so you don't have to)

- A from-scratch second implementation (Rust reader) is gated against all 47
  conformance vectors in CI; a Rust writer round-trips to the .NET reader.
- Deterministic CBOR enforcement, strict length checks, fail-closed parsing,
  and a portable negative-vector set covering every fail-closed MUST.
- Self-identified deviations and limitations are disclosed, not hidden.

## The frozen target and how to verify

Everything needed to reproduce the evidence is in one place:
**`docs/REVIEWER-PACKET.md`** — the frozen target (spec tag, vector-pack
fingerprint), exact commands for `dotnet test`, the Rust conformance run, and
byte-deterministic vector regeneration, plus the disposition of every known
limitation.

## What feedback is most useful

"This combiner claim is wrong because X." "This is underspecified at Y." "This
is fine but you can't claim Z." Negative, specific, and early beats polite and
late. Findings will be incorporated or the rationale for not doing so recorded
in the open — that is the whole point of keeping it a draft.

**Contact:** open a [GitHub issue](https://github.com/systemslibrarian/PostQuantum.FileFormat/issues)
or reach the maintainer per `MAINTAINERS.md`.
