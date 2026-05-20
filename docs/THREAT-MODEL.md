# PQF Threat Model

This document is the explicit threat model PQF is designed against. It
exists so reviewers can quickly determine whether PQF is the right tool
for a given problem — and, equally important, when it is not.

The format is **fail-closed by design**: any deviation from the wire
format terminates processing with a typed error. There are no permissive
parsing paths. Most of the assets below are protected by refusing inputs,
not by recovering from them.

## Scope

In-scope:

- A single `.pqf` file at rest on a storage medium (disk, object store,
  email attachment, etc.).
- The reference reader, writer, and CLI tooling that produces and
  consumes such files.

Out of scope:

- Transport security (TLS, Noise, QUIC).
- Endpoint compromise (malware on the encrypting or decrypting host).
- Side-channel attacks beyond what the underlying primitive
  implementations resist; see `docs/SIDE-CHANNEL-POSTURE.md`.
- Anonymity / metadata privacy. The header is unencrypted; presence,
  recipients, signer, chunk size, and timestamp are all visible.
- Key distribution, trust establishment, or key rotation policy.

## Assets

| Asset | Property to preserve |
|---|---|
| **Plaintext file contents** | Confidentiality, integrity |
| **Identification of the file's authentic signer** (when signed) | Authenticity, non-repudiation (within the limits of the signing key holder's discretion) |
| **The recipient's identity (private key)** | Confidentiality — must not be recoverable from observation of a `.pqf` file or a decryption attempt |
| **Parser process** | Liveness — a malformed input MUST NOT crash, hang, or consume unbounded resources |

## Adversary model

We assume the adversary:

- Has full read access to one or more `.pqf` files.
- Can produce arbitrary mutated `.pqf` files and submit them to a
  reader (the reader is the security boundary).
- May possess a future cryptographically-relevant quantum computer
  ("harvest now, decrypt later" — this is the primary motivation).
- Does NOT have the recipient's private key.
- Does NOT have the signer's private key (for assets that depend on
  authenticity).
- Does NOT have execution access on the decrypting host (endpoint
  compromise is out of scope).

We make no assumptions about the adversary's compute budget against the
hybrid construction — the security goal is that *one* of the two
primitives (classical X25519 + AES-256-GCM, or post-quantum ML-KEM-1024)
remaining unbroken is sufficient for confidentiality.

## STRIDE summary

| Threat class | Asset | PQF mitigation | Status |
|---|---|---|---|
| **Spoofing** — forged file claims to be from a signer | Authenticity | Hybrid signature (Ed25519 ∧ ML-DSA-87). Both halves must verify; either failure refuses the file. | Mitigated when signed; impossible to mitigate on unsigned files. |
| **Tampering** — bit-flip in ciphertext | Confidentiality, integrity | Per-chunk AES-GCM auth tag bound to `file_id ‖ chunk_index ‖ is_final`. Any flip refuses the chunk. | Mitigated. |
| **Tampering** — bit-flip in header CBOR | Same | Header signature (when signed) covers header bytes. Even when unsigned, header is required to be deterministically encoded; non-canonical encodings are refused. | Mitigated when signed; unsigned files are tamper-detectable but not tamper-attributable. See open question §6 below. |
| **Tampering** — bit-flip in footer | Footer integrity | When the file is signed, the file signature covers the footer. When unsigned, footer is currently not AEAD-bound — see "Open questions" below. | Mitigated when signed; open question on unsigned files. |
| **Tampering** — truncation | Both | Footer reconciliation: chunk count and plaintext-byte tally are checked against the footer. Truncation that loses a chunk fails the count check; truncation that loses bytes from the trailing chunk fails the tally. | Mitigated. |
| **Tampering** — chunk reorder, replay, splice | Both | AAD binding to `chunk_index` and `is_final`. A reordered or duplicated chunk decrypts under the wrong AAD and refuses. Cross-file splicing refused because `file_id` is part of AAD. | Mitigated. |
| **Repudiation** — signer denies authorship | Non-repudiation | Hybrid signature carries both classical and PQ evidence. | Mitigated as far as the signing keys are kept private. PQF does not solve key-binding (i.e., "is this the right Alice"); that is the caller's job. |
| **Information disclosure** — header metadata | Metadata privacy | Out of scope. Header is plaintext by design. | Documented limitation. |
| **Information disclosure** — recipient private key via side channel | Confidentiality of key | Per `docs/SIDE-CHANNEL-POSTURE.md`: wrapper code does its recipient-trial in constant time over the list of recipient blocks; primitives are provided by BouncyCastle for .NET (managed C#) which does not claim full CT against power/EM/microarchitectural side channels. | Wrapper-CT mitigated; primitive-CT inherited. |
| **Information disclosure** — error-message leakage | Same | All refusal errors carry a typed `PqfRefusalReason`. No reason value distinguishes "wrong recipient" from "wrong key" in a way that lets an attacker learn which recipients can decrypt a given file beyond what the unencrypted recipient list already reveals. | Mitigated. |
| **Denial of service** — malformed file consumes unbounded resources | Liveness of reader | Hard caps: header ≤ 1 MiB (spec §3), chunk_size ≤ 16 MiB. Streaming reader buffers at most the header + one in-flight chunk. Authenticated mode stages above 100 MiB to a 0600 `DeleteOnClose` tempfile so the file signature can be verified before plaintext is released. | Mitigated. |
| **Denial of service** — algorithmic complexity attack on parser | Same | Deterministic CBOR parser; no recursion past structural depth implied by the closed header schema; map-key ordering is checked by direct comparison, not by sort. | Mitigated. |
| **Elevation of privilege** — parser bug yields code execution | All assets | The reference implementation is managed .NET; the parser performs no native/unsafe code or P/Invoke. Refusal paths are exercised by negative test vectors (`tests/PostQuantum.FileFormat.TestVectors/` and the fuzz harness `tests/PostQuantum.FileFormat.Fuzz/`). | Mitigated by language choice + tests; defense-in-depth via fuzzing and CodeQL. |

## Specific attacker scenarios

### "Harvest now, decrypt later"

The adversary records ciphertext today and stores it indefinitely,
intending to decrypt once a CRQC (cryptographically-relevant quantum
computer) exists.

- Confidentiality holds as long as ML-KEM-1024 holds, even if X25519 is
  fully broken by quantum methods.
- Confidentiality also holds as long as X25519 + AES-256 hold, even if
  ML-KEM-1024 is later broken by classical cryptanalysis.

This is the **central** design goal. If you do not need protection
against this attacker, age or libsodium are simpler tools.

### Active mutation attacker

The adversary modifies a `.pqf` file in transit or at rest, hoping the
reader will produce a plaintext that is not the original.

- Any bit-flip in the header refuses the file (deterministic-CBOR
  re-encoding check, or signature verification when signed).
- Any bit-flip in a chunk refuses that chunk (GCM tag check).
- Any bit-flip in the footer refuses the file (either via the file
  signature when signed, or via the count/byte-tally reconciliation).

The reader never emits a "partial" plaintext that the attacker chose.

### Streaming-mode caller who ignores post-hoc errors

In streaming mode the reader emits verified chunks as they arrive, then
checks the footer (and file signature, when present) at end-of-stream.
A caller that *deliberately* discards the trailing error can be tricked
into accepting a truncated or footer-corrupted file.

- The streaming-mode contract requires the caller to consume the
  trailing result. This is enforced at the API level by a
  `MustUseReturnValue` attribute on `PqfStreamingPipeline`'s trailer
  method.
- Authenticated mode exists precisely for callers who cannot guarantee
  they will handle the post-hoc error.

### Forged recipient block

An attacker constructs a `.pqf` file with a recipient block whose
public-key material is malformed, or a KEM ciphertext that decapsulates
to a different shared secret on different libraries.

- KEM implicit-rejection: ML-KEM-1024's spec-defined implicit-rejection
  behavior is preserved through to the recipient-trial loop. Failure to
  unwrap the DEK with one recipient block proceeds to the next without
  branching on the failure reason, preserving constant-time behavior
  over the list of recipient blocks.
- A forged ciphertext is mathematically indistinguishable from one the
  attacker simply made up; it cannot extract the recipient's private key.

## Open questions

These are not unmitigated threats but design points the author explicitly
solicits review on. They are listed verbatim in
`spec/PQF-DESIGN-RATIONALE-v1.md` §11; replicated here for visibility:

1. Whether header-signature and file-signature messages should carry
   distinct domain-separation prefixes.
2. Whether the footer should be AEAD-bound on unsigned files. Currently,
   tamper-evidence on the footer of an unsigned file is provided by the
   count/byte-tally reconciliation, not by an AEAD tag.

## What PQF deliberately does NOT promise

- **Anonymity.** The header is plaintext.
- **Forward secrecy.** PQF is for files at rest. Recipient long-term
  keys are used directly; if a recipient's key is later compromised,
  all `.pqf` files encrypted to that recipient become decryptable.
  Add ephemeral key wrapping at the application layer if you need FS.
- **Deniability.** When signed, signatures are non-repudiable.
- **Protection against endpoint compromise.** If malware reads the
  decrypted plaintext, no on-disk format helps.

## How to report a threat-model gap

If you believe PQF does not mitigate a threat it should mitigate — or
mitigates one it shouldn't claim to — open a
[spec-review issue](.github/ISSUE_TEMPLATE/spec-review.yml). For
exploitable findings, use the [private security
advisory](https://github.com/systemslibrarian/PostQuantum.FileFormat/security/advisories/new)
channel; see [SECURITY.md](../SECURITY.md).
