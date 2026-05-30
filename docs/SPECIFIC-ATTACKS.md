# Specific attacks PQF resists (and how)

This document walks through eight concrete attack scenarios — each with a
named adversary, specific capabilities, the exact wire-format mechanism
that defends against it, and an honest note when the defense has limits.

It is meant to be read alongside [`docs/THREAT-MODEL.md`](./THREAT-MODEL.md)
(which is the STRIDE-shaped general model) and the spec sections cited in
each scenario. Where this document and the spec disagree, the spec is
authoritative.

## Scenario 1 — Harvest now, decrypt later (HNDL) with a quantum computer

**The adversary.** A nation-state-scale actor records `.pqf` ciphertext
files in 2026 and stores them indefinitely. In some future year (2035?
2045? unknown) they gain access to a cryptographically-relevant quantum
computer (CRQC) capable of running Shor's algorithm against Curve25519
in tractable time.

**What they have.** Unlimited offline computation in the post-CRQC era.
The complete `.pqf` file. No private key.

**What PQF gives them.** Nothing. The X-Wing combiner
(`KEK = SHA3-256(ss_M || ss_X || ct_X || pk_X || label)`, spec §2.4)
binds the per-recipient KEK to both the ML-KEM-768 shared secret and
the X25519 shared secret. A CRQC that breaks Curve25519 recovers `ss_X`
but not `ss_M` — and X-Wing's IND-CCA proofs in ROM and QROM (Barbosa
et al., 2024) say that's not enough: the SHA3-256 invocation requires
both inputs to be the legitimate values, and ML-KEM-768 is believed to
resist quantum attacks under the Module-LWE assumption.

**Honest limit.** This defense survives **only if at least one of**
ML-KEM-768 or X25519 remains secure. If BOTH fall, the file is gone.
That's the entire point of being hybrid; the cost is doubled key
material and a slightly heavier combiner. The single-primitive failure
modes are what hybrid encryption is designed for. (Spec §8.1.)

## Scenario 2 — Substituted ciphertext (cross-recipient, same file)

**The adversary.** A recipient with a valid identity for slot `i` in a
multi-recipient file tries to recover plaintext intended for slot `j`
by feeding their own KEK into a different recipient block.

**What they have.** Their own valid `(sk_X, sk_M)` keypair; the full
header (which includes every recipient's `(ct_X, ct_M, wrapped_dek,
wrapped_dek_nonce)`); the wrapped DEK they're attacking.

**What PQF gives them.** Nothing. Three layers of defense:

1. X-Wing's combiner binds the recipient's own X25519 public key
   (`pk_X`) into the SHA3-256 input. The recipient's KEK is structurally
   different from every other recipient's KEK, even if the `ss_X` /
   `ss_M` values somehow collided.
2. The DEK-wrap AEAD AAD carries `file_id (16) || recipient_index
   (uint32 BE)` (spec §2.4). A KEK derived for slot `i` cannot unwrap a
   wrap targeted at slot `j` because the AADs differ; AES-GCM tag
   verification fails.
3. Both checks are constant-time inside the recipient trial
   (`AuthenticatedModeDecryptor.ResolveDek`); the attacker doesn't get
   side-channel signal about which slot would-have-matched.

**Honest limit.** None on this scenario. (Spec §8.7.)

## Scenario 3 — Forged signed file (signing key compromise simulation)

**The adversary.** Wants to deliver a malicious `.pqf` file that the
recipient will trust as coming from a known signer. Does not have the
signer's private keys.

**What they have.** Public knowledge of the signer's hybrid public
keypair. A genuine signed file from that signer (which they may
modify). Network position to deliver the modified file.

**What PQF gives them.** Nothing — provided the recipient uses
Authenticated Mode (the default). The hybrid signature requires BOTH
Ed25519 AND ML-DSA-87 to verify
(`HybridSigner.Verify` uses bitwise `&`, not short-circuit `&&`, so a
failure in either half refuses the file). Both halves are domain-
separated: header signature over `"PQF1-header-sig-v1" || header_bytes`,
file signature over `"PQF1-file-sig-v1" || file_id || sha256(chunks) ||
footer` (spec §6.2). Cross-context replay is not possible.

**Honest limit.** If the adversary actually does steal the signer's
private keys, PQF cannot detect that. No format can. The
defense-in-depth is the hybrid: both Ed25519 and ML-DSA-87 keys must
leak simultaneously.

## Scenario 4 — Streaming-mode plaintext disclosure on a malicious file

**The adversary.** Crafts a `.pqf` file with valid recipient blocks but
a tampered footer (or an invalid file signature). Tricks the recipient
into running in Streaming Mode, which releases plaintext per-chunk
before the final verification.

**What they have.** Knowledge that the recipient uses Streaming Mode
for performance.

**What PQF gives them.** The chunks they tampered. The recipient WILL
see those bytes — that's the Streaming Mode tradeoff and the spec is
explicit about it (§6.4.2). What PQF **forces** is that the failure
signal cannot be silent: the streaming decryptor's return type carries
a `[MustUseReturnValue]` attribute (C# wrapper) so the caller cannot
discard the post-hoc verification result without a compiler warning,
and the failure signal propagates as an exception or non-zero result by
contract (spec §6.4.2). The format makes "I ignored the failure on
purpose" cost an explicit code change.

**Honest limit.** Streaming Mode is the one place PQF's fail-closed
discipline bends. A caller who *deliberately* ignores the post-hoc
result and acts on emitted bytes can be tricked. Authenticated Mode
exists for exactly this reason and is the default everywhere
production-shaped APIs expose a choice.

## Scenario 5 — Chunk reorder / splice / replay across files

**The adversary.** Has two `.pqf` files that share a recipient. Wants
to splice a chunk from file A into file B, hoping the recipient accepts
the spliced file.

**What they have.** Both ciphertext files. The recipient's identity
(or the ability to observe the recipient's behavior on the spliced
file).

**What PQF gives them.** Nothing. Every chunk's AEAD AAD binds
`file_id (16) || chunk_index (8 BE) || is_final (1)` (spec §5.2).
`file_id` differs between files, so a chunk from file A has a
spliced-in tag that no longer authenticates under file B's chunk key
derivation. `chunk_index` differs between positions, so internal
reordering fails the same way. `is_final` prevents the
swap-last-chunk-for-non-last trick. (Spec §8.5.)

**Honest limit.** None on this scenario.

## Scenario 6 — Truncation to empty (the unsigned-file footer gap)

**The adversary.** Replaces an unsigned `.pqf` file with a syntactically
valid empty file (zero chunks, valid footer claiming zero chunks, zero
plaintext bytes).

**What they have.** Filesystem write access to the unsigned `.pqf` file
at rest.

**What PQF gives them.** Plausible deniability. The footer reports
zero chunks; AEAD never runs (no chunks to authenticate); footer
validation passes (counts match). The recipient sees a valid empty
plaintext.

**Honest limit.** Real. This is the documented gap in unsigned files
(threat model §8.4 + rationale §11.7). The mitigation is to **sign the
file** — when signed, the file signature covers the footer (spec §6.2
step 9), so erasure-to-empty changes the footer-hash input and the
signature fails to verify. Unsigned files explicitly trade integrity
for the no-signer-key convenience case, and the spec calls this out
as accepted behavior, not a bug.

## Scenario 7 — Malicious recipient block (forged ML-KEM ciphertext)

**The adversary.** Crafts a `.pqf` file with a recipient block whose
`pqc_ct` is a deliberately malformed ML-KEM-768 ciphertext. Hopes that
the decapsulation step leaks information about the recipient's private
key, or causes the recipient to decapsulate to an attacker-known shared
secret.

**What they have.** The recipient's public key (which is also encoded
in their identity file). The ability to deliver a crafted `.pqf` file.

**What PQF gives them.** Nothing. Three independent reasons:

1. ML-KEM-768 uses **implicit rejection** (FIPS 203): on malformed
   ciphertext, decap returns a pseudorandom value rather than a failure
   signal. The recipient cannot tell from the decap output whether the
   ciphertext was legitimate; it only finds out at the DEK-wrap AEAD
   step.
2. PQF's recipient trial is constant-time over the list of recipient
   blocks (spec §6.5), so the attacker doesn't get timing signal about
   which block PQF thinks is malformed.
3. The X-Wing combiner mixes `ct_X` (the X25519 ephemeral) and `pk_X`
   (the recipient's long-term key) into the KEK derivation. Even if a
   forged ML-KEM ciphertext somehow gave the attacker a known `ss_M`,
   the attacker still needs to know the recipient's `ss_X`, which
   requires the recipient's X25519 private key.

**Honest limit.** None on this scenario.

## Scenario 8 — Side-channel attacker on the decryption host

**The adversary.** Has co-tenancy on the same physical CPU as the
recipient, or physical proximity (power analysis, EM emanation). Can
observe wall-clock timing, power draw, or RF signals from the
recipient's machine during decryption.

**What they have.** Detailed timing / power / EM traces during one or
more decryption operations.

**What PQF gives them.** Whatever the underlying primitive provides.
PQF's wrapper code is constant-time over the recipient trial and over
hybrid-signature verification (the bitwise `&` is the load-bearing
detail). The ML-KEM-768 / ML-DSA-87 implementations come from the
native BCL on .NET 10, which route through platform crypto — OpenSSL
3.5+ on Linux (libcrypto's ML-KEM is hardened against the published
timing attacks), CNG on Windows 11 / Server 2025. **PQF does not claim
its wrapper code closes a side channel that exists in the primitive.**
It claims it doesn't add new ones.

**Honest limit.** Significant. Side-channel-hardened cryptography on a
2026 commodity CPU running a managed runtime is a much weaker claim
than what an HSM provides. PQF is a file format, not a key custody
solution. If your threat model includes co-tenant or physical-access
attackers against keys whose compromise you cannot accept, those keys
should live in an HSM and PQF's wrappers should call into the HSM via
an `ICryptoProvider` shim. See [`docs/SIDE-CHANNEL-POSTURE.md`](./SIDE-CHANNEL-POSTURE.md).

## What this document does NOT do

- It does not enumerate every attack that fails. STRIDE coverage lives
  in [`docs/THREAT-MODEL.md`](./THREAT-MODEL.md); refusal-condition
  coverage lives in the negative test vectors
  (`test-vectors/v1/cases/TV-NEG-*.pqf`).
- It does not assert PQF is *secure* in a formal sense. The X-Wing
  combiner has external proofs (Barbosa et al., 2024); the overall PQF
  assembly does not.
- It does not list active research-frontier attacks against ML-KEM or
  ML-DSA. Those are tracked at https://csrc.nist.gov/projects/post-quantum-cryptography
  and PQF's posture is to follow NIST guidance.
