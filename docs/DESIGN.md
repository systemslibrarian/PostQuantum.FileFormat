# PQF Design — A Narrative

This is a long-form explanation of why PQF is what it is, written for
people who care about file formats and security but who are not
cryptographers. The spec ([`spec/PQF-SPEC-v1.md`](../spec/PQF-SPEC-v1.md))
and the design rationale
([`spec/PQF-DESIGN-RATIONALE-v1.md`](../spec/PQF-DESIGN-RATIONALE-v1.md))
are the authoritative documents — this one trades precision for
narrative.

## The problem in one paragraph

A file encrypted today should still be unreadable to an adversary
twenty years from now. The currently-deployed asymmetric cryptography
(RSA, ECDH over Curve25519) is conjectured to be broken by a
sufficiently large quantum computer running Shor's algorithm. We
don't have one of those yet, but we have something nearly as bad:
adversaries with resources to record encrypted traffic and store it
indefinitely, waiting for the day they can decrypt it. That is the
"harvest now, decrypt later" attacker. Files that need to remain
confidential for decades — legal archives, source code under embargo,
medical records, intelligence material — are under threat *today*
from this attacker, even though no one has a quantum computer yet.

The cryptography community has converged on a response: hybrid
constructions that combine a classical primitive (X25519, Ed25519)
with a post-quantum primitive (ML-KEM, ML-DSA) so that confidentiality
holds as long as *either* primitive remains unbroken. NIST standardized
ML-KEM and ML-DSA in FIPS 203 / FIPS 204 in 2024.

PQF is a file format that bakes that hybrid construction in as the
default, with no flag to forget.

## Three design principles, in priority order

### 1. Fail-closed by construction

The single most consequential design choice. PQF readers refuse on:

- any malformed structure
- any unknown field at any nesting level
- any reserved bit set
- any length mismatch
- any non-canonical encoding
- any integrity failure
- any algorithm string the reader does not literally recognize

There are no permissive paths. No "best effort." No "skip this section
and continue." When a PQF reader rejects a file, it does so with a
typed `PqfRefusalReason` and zero plaintext released.

Why so harsh? Because every "best effort" path in a security-relevant
parser is a future CVE. The OpenPGP world spent decades demonstrating
this. Strict parsing is not a usability problem when the file format
exists to protect data: a file that won't open is recoverable; a file
that *appears* to open but produces attacker-chosen output is not.

### 2. The spec is the source of truth, not the implementation

PQF is "spec-first, not implementation-first." That phrase is a real
constraint on the project, not a slogan. It means:

- The wire format is normative. The .NET reference implementation
  exists to prove the spec is implementable, not the other way
  around. Where the implementation and spec disagree, the spec wins.
- Anything that affects bytes-on-disk gets a spec PR first.
- A second-source implementation in a different language (the Rust
  reader at `impl/rust/pqf-reader`) exists explicitly to catch the
  case where two implementers reading the same spec arrive at
  different code. That gap is, by definition, a spec defect — and
  finding spec defects before v1.0.0 freezes is the whole point of
  the cross-impl conformance gate.

This is unusual for software projects but normal for protocol work
(TLS, HTTP, CBOR itself). The discipline pays off when other
implementations appear.

### 3. Hybrid by default, not as an extension

Lots of formats added "post-quantum mode" as a feature flag in 2023
or 2024 — usually with the classical primitive as the default and PQ
as the opt-in. PQF takes the opposite position: hybrid is the only
path. There is no classical-only PQF, and there will not be one.

The reason is harvest-now-decrypt-later. A file format that ships PQ
as a flag will produce mostly classical files for years before
operators flip the flag. Those files will be vulnerable to an attacker
who already has the ciphertext. By making PQ mandatory, every PQF
file is harvest-resistant from day one.

## Choices that follow from the principles

### Why CBOR for the header

CBOR has a deterministic encoding profile (RFC 8949 §4.2.2): a parser
can re-encode a value and demand the result be byte-identical to the
input. That converts "is this header canonical?" from a hand-written
check into a structural property. Combined with a closed schema (no
unknown fields), it gives us almost-free tamper-evidence on the
header even when the file is unsigned.

JSON would have worked, but the deterministic-encoding rules for
JSON are weaker and require more hand-written validation.

### Why per-chunk HKDF with a fixed zero nonce

NIST SP 800-38D requires unique nonces for each AES-GCM call under
the same key. The natural way to achieve that — a random nonce per
chunk — costs 12 bytes per chunk and exposes us to nonce-reuse risk
if the RNG is bad.

PQF derives a unique key for every chunk via HKDF-Expand from the
DEK, with the chunk index in the info string. Because each chunk has
its own key, the nonce can be the fixed zero string with no nonce-
reuse risk: "same nonce, different key" is fine. This saves 12 bytes
per chunk and removes a class of RNG-quality bugs.

### Why two decryption modes

Authenticated Mode (the default) buffers verification before
releasing any plaintext. That's the safe choice. But it requires
either holding the plaintext in memory or staging to disk, and for
files that don't fit either, Streaming Mode lets the caller pipe
verified chunks to a downstream sink.

Streaming Mode is dangerous if the caller forgets to check the
post-stream verification result — chunk-level integrity holds, but
file-level integrity (signature, footer reconciliation) is checked
after the last chunk. So PQF's API marks the streaming-mode result
with `[MustUseReturnValue]` and gives it a non-trivial type that the
compiler will warn about discarding. See [`STREAMING.md`](./STREAMING.md)
for the decision matrix.

### Why a 20-byte footer

The footer carries `chunk_count` and `plaintext_bytes` (both u64 BE,
plus a 4-byte magic). Those two values reconcile the chunk stream:
truncation that loses a whole chunk fails the count, truncation that
loses bytes from the trailing chunk fails the tally. The footer is
intentionally tiny so even pre-v1.0.0 readers can validate it
cheaply during streaming.

The open question — should the footer be AEAD-bound on unsigned
files? — is one of the design choices we've left for review in
[`PQF-DESIGN-RATIONALE-v1.md`](../spec/PQF-DESIGN-RATIONALE-v1.md) §11.

### Why we are not building TLS

PQF protects files at rest. It does not protect connections, sessions,
streams, messages, or any in-flight thing. Adding any of those would
mean shipping a different threat model, and the project's job is
exactly the file-at-rest threat model. If you need an in-flight
hybrid PQ story, see TLS hybrid key exchange (X25519MLKEM768) — it
exists for the same reasons PQF does, but for the other end of the
stack.

## What we don't know yet

Some things are deliberately under-specified pending review:

- **Footer AEAD-binding on unsigned files.** Covered above.
- **Constant-time recipient trial under adversarial recipient lists.**
  We documented our posture in [`SIDE-CHANNEL-POSTURE.md`](./SIDE-CHANNEL-POSTURE.md)
  and instrumented it in `RecipientTrialConstantTimeTests`, but a
  rigorous review by someone who lives in side-channel land would
  improve our confidence.

These open questions are not blockers for the project being useful
today; they are blockers for v1.0.0 wire-format freeze.

## Where to go from here

- [`spec/PQF-SPEC-v1.md`](../spec/PQF-SPEC-v1.md) — the normative
  specification.
- [`spec/PQF-DESIGN-RATIONALE-v1.md`](../spec/PQF-DESIGN-RATIONALE-v1.md)
  — the technical version of this narrative.
- [`THREAT-MODEL.md`](./THREAT-MODEL.md) — the per-asset STRIDE
  analysis.
- [`COMPATIBILITY.md`](./COMPATIBILITY.md) — the versioning contract.
- [`STREAMING.md`](./STREAMING.md) — which decryption mode to use.
- [`spec/ietf/draft-clark-pqf-00.md`](../spec/ietf/draft-clark-pqf-00.md)
  — the Internet-Draft skeleton.
- [`spec/symbolic/`](../spec/symbolic/) — formal models, work in progress.
