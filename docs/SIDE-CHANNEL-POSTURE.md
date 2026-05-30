# Side-Channel Posture

**Status:** EXPERIMENTAL. This document describes what the PostQuantum.FileFormat
reference implementation does and does not claim with respect to side-channel
resistance, and lists the upstream guarantees it inherits. It is intended for
cryptographic reviewers and for downstream implementers who need to decide
whether PQF's posture is acceptable for their threat model.

This document covers the **.NET reference implementation** in this repository.
The PQF wire format itself imposes no constant-time requirement on
implementations; that is a property of the implementer's chosen library stack.

---

## TL;DR

The reference implementation does not claim side-channel resistance. It
inherits whatever posture its underlying primitives provide:

- **`System.Security.Cryptography` (BCL)** for X25519, Ed25519, AES-GCM,
  HKDF-SHA256, SHA-256, and `RandomNumberGenerator`. On modern .NET
  (8 / 9 / 10) on x64 Linux, AES-GCM goes through AES-NI + CLMUL, which is
  constant-time on the CPU. The ECC primitives delegate to OpenSSL on Linux
  and CNG on Windows; both upstreams have public constant-time claims for the
  Curve25519 family. None of these claims is restated by Microsoft in the BCL
  documentation.
- **BouncyCastle for .NET** (`Org.BouncyCastle.Crypto.MLKemEngine`,
  `MLDsaSigner`) for ML-KEM-768 and ML-DSA-87. This is managed C# code.
  BouncyCastle does **not** publish a constant-time claim against power, EM,
  or microarchitectural side channels for these implementations.

The wrapper code in PQF (the parts the maintainers control) has been audited
to ensure it does not introduce a new timing leak on top of what the
primitives provide. That audit is summarised below.

---

## What "side-channel resistance" means here

A side channel is any observable other than the algorithmic output that
depends on a secret. The relevant categories for PQF are:

| Channel | Threat scenario | What can defend |
|---|---|---|
| **Wall-clock timing** | A network or co-tenant attacker measures how long PQF takes to decrypt a probe file and infers something about the recipient identity, the plaintext, or the chosen recipient slot. | Constant-time primitives + constant-iteration trial loops. |
| **Cache timing** | A co-tenant on the same physical CPU runs Flush+Reload or Prime+Probe to learn key bits from a victim PQF process. | Constant-memory-access primitives. Requires bare-metal microarchitectural tooling to test. |
| **Branch-predictor / speculative** | Spectre-class attacks against a victim PQF process. | Microcode mitigations + constant-time primitives. Out of scope for application-level review. |
| **Power / EM** | Physical proximity to the device running PQF. | Hardware-level countermeasures. PQF cannot defend at the software layer. |

PQF makes claims about wall-clock timing only at the **wrapper level** — that
is, the recipient-trial loop and the chunk-decrypt loop run in constant
iteration regardless of which recipient slot matches and regardless of which
chunks authenticate. For everything below that layer, PQF inherits its
primitives' posture.

---

## What we control: wrapper-level audit

This is the audit of every PQF-controlled code path that touches secret
material. Each row lists the file, the operation, what the wrapper does on
top of the primitive, and the verdict.

| File | Operation | Wrapper behaviour | Verdict |
|---|---|---|---|
| [`HybridKem.cs`](../src/PostQuantum.FileFormat/Crypto/HybridKem.cs) `Encapsulate` / `Decapsulate` | Thin shim over `XWingKem`. Both KEM halves (X25519 + ML-KEM-768) always run. | All work delegated to `XWingKem`. | No additional leak. |
| [`XWingKem.cs`](../src/PostQuantum.FileFormat/Crypto/XWingKem.cs) `Encapsulate` / `Decapsulate` | X-Wing combiner per draft-connolly-cfrg-xwing-kem: `KEK = SHA3-256(ss_M \|\| ss_X \|\| ct_X \|\| pk_X \|\| "\.//^\")`. | Intermediate shared secrets (`ss_M`, `ss_X`) and the X25519 ephemeral private key are zeroed via `SecureZero.Clear` in `finally` blocks before return. SHA3-256 update sequence is data-independent (no branching on secret-derived state). | No additional leak. |
| [`HkdfCombiner.cs`](../src/PostQuantum.FileFormat/Crypto/HkdfCombiner.cs) `DeriveChunkKey` | Per-chunk HKDF-Expand from the 32-byte DEK with `"PQF1-chunk-v1" \|\| chunk_index_be64` as info. Unrelated to the KEM combiner. | Heap copies of DEK material are wrapped in `try/finally` with `SecureZero.Clear`. | No additional leak. |
| [`DekWrapper.cs`](../src/PostQuantum.FileFormat/Crypto/DekWrapper.cs) `Wrap` / `Unwrap` | AES-256-GCM wrap of the 32-byte DEK with `file_id \|\| recipient_index (uint32 BE)` as AAD. The AAD carries the per-file and per-recipient binding that X-Wing's combiner has no salt slot for. | Tag comparison is performed by `AesGcm.Decrypt` (BCL); on failure the wrapper zeros its scratch DEK buffer and returns `null`. There is no manual tag compare in the wrapper. AAD buffer is zeroed in `finally`. | No additional leak. The exception throw on tag failure is itself a wall-clock signal, but the wrapper does not amplify it. |
| [`AuthenticatedModeDecryptor.cs`](../src/PostQuantum.FileFormat/File/AuthenticatedModeDecryptor.cs) `ResolveDek` | Trial-decrypt every recipient slot with the supplied identity. | The loop runs for every recipient regardless of which slot matches. Both `HybridKem.Decapsulate` and `DekWrapper.Unwrap` execute on every iteration. The post-iteration branches (`continue` on no-match, pointer assign on first match, zero-and-discard on subsequent matches) are all O(1) work, dominated by the millisecond-scale ML-KEM decap that runs unconditionally. | Constant iteration. The branches *are* observable but the dominant work is constant. |
| [`AuthenticatedModeDecryptor.cs`](../src/PostQuantum.FileFormat/File/AuthenticatedModeDecryptor.cs) chunk loop | AES-256-GCM decrypt every chunk; refuse on first AEAD failure. | This is **not** constant-time across chunks: a tampered chunk causes early refusal. This is intentional (fail-closed) and matches the spec. The information leaked is which chunk index first failed, which is already public from the file structure. | No leak of secret material. |
| [`StreamingModeDecryptor.cs`](../src/PostQuantum.FileFormat/File/StreamingModeDecryptor.cs) | Same as Authenticated mode but releases plaintext per-chunk before signature verification. | Same constant-iteration recipient trial. Per-chunk early-refusal behaviour identical to Authenticated mode. | No leak of secret material. |
| [`HybridSigner.cs`](../src/PostQuantum.FileFormat/Crypto/HybridSigner.cs) `Verify` | Verify Ed25519 + ML-DSA-87 signature halves; return `true` only if both succeed. | Uses bitwise `&` rather than `&&` so both halves always execute (L-3 fix). A timing observer cannot distinguish "Ed25519 failed" from "Ed25519 passed but ML-DSA-87 failed". | No additional leak. |
| [`BouncyCastleCryptoProvider.cs`](../src/PostQuantum.FileFormat/Crypto/BouncyCastleCryptoProvider.cs) | Bridges PQF's `ICryptoProvider` interface to BouncyCastle. Each per-call wrapper materializes the caller's `ReadOnlySpan<byte>` private key into a managed `byte[]` because BouncyCastle's parameter classes take `byte[]+offset`. | Each intermediate `byte[]` private-key copy is zeroed via `SecureZero.Clear` in `finally` (M-5 fix). BouncyCastle's *internal* copies inside `*PrivateKeyParameters` are out of our control. | No additional leak. |
| [`SecureZero.cs`](../src/PostQuantum.FileFormat/Crypto/SecureZero.cs) | Zero a `byte[]` / `Span<byte>`. | Calls `CryptographicOperations.ZeroMemory`, which is documented to not be optimised away by the JIT. | Best available within managed code. |

**Result:** the maintainers do not see a wrapper-level path that leaks secret
material via wall-clock timing in a way that is not already implied by the
primitive choice or by intentional fail-closed behaviour.

This audit was performed by reading source. It has **not** been validated by
microbenchmark or by an external reviewer.

---

## What we inherit: primitive-level posture

This is the matrix of primitives PQF uses, the upstream provider, and what
that provider claims (or does not claim) about side-channel resistance. The
maintainers have **not** independently verified any of these claims; the
table is a guide for reviewers, not an endorsement.

| Primitive | Provider on .NET 8 | Provider on .NET 10+ when platform supports it | Public CT claim? | Notes |
|---|---|---|---|---|
| X25519 | BouncyCastle `X25519Agreement` (for cross-runtime uniformity; the BCL Curve25519 surface is not uniform across platforms). | Same — BouncyCastle. The BCL bridge does not currently route X25519 because the BCL surface is platform-shaped. | BouncyCastle: no explicit claim. The reference C# implementation uses field arithmetic that is *intended* to be constant-time but is not formally verified. | Curve25519 is designed to make constant-time implementation natural; whether this particular implementation achieves it on RyuJIT is not a claim BouncyCastle makes. |
| ML-KEM-768 | BouncyCastle `MLKemEngine`. | **BCL `System.Security.Cryptography.MLKem`** when `MLKem.IsSupported` is `true` on the host (typically: .NET 10+ runtime AND a platform crypto stack that exposes ML-KEM, e.g. modern OpenSSL on Linux or CNG on Windows). Falls back to BouncyCastle when not. Selection is automatic via [`BclCryptoProvider`](../src/PostQuantum.FileFormat/Crypto/BclCryptoProvider.cs); the active provider is logged once at process start. | BCL: inherits whatever the platform crypto provider claims. Microsoft does not restate side-channel claims at the BCL surface, but the underlying providers (OpenSSL ML-KEM, CNG ML-KEM) may. BouncyCastle: no public constant-time claim. | NIST FIPS 203 specifies ML-KEM but does not mandate constant-time implementation. The BC implementation is managed C# and subject to JIT-level non-determinism; the BCL implementation is platform-backed and routes through a native provider. |
| ML-DSA-87 | BouncyCastle `MLDsaSigner`. | **BCL `System.Security.Cryptography.MLDsa`** under the same conditions as ML-KEM. Falls back to BouncyCastle when not. | Same as ML-KEM: BCL inherits the platform claim, BC has no public claim. | Same caveats as ML-KEM. ML-DSA signing in particular has historically been a target of side-channel research because of the rejection sampling step in Dilithium-family schemes; routing it through a platform-backed implementation when available is the main reason the BCL bridge exists. |
| Ed25519 | BouncyCastle `Ed25519Signer`. | Same migration path. | BouncyCastle: no explicit claim. Ed25519's deterministic nonce derivation removes the most common side-channel target (RNG-based nonce reuse) from this primitive. | Ed25519 is, like X25519, designed for natural constant-time implementation; the same JIT caveat applies. |
| AES-256-GCM | BCL `System.Security.Cryptography.AesGcm`. | Same. | On x64 with AES-NI + CLMUL: hardware-accelerated and constant-time at the CPU level. On platforms without those instructions: software fallback with no constant-time claim. | The BCL picks at runtime. PQF does not opt out of the hardware path. |
| HKDF-SHA256 | BCL `System.Security.Cryptography.HKDF`. | Same. | SHA-256 in the BCL goes through OpenSSL on Linux (constant-time) and CNG on Windows (constant-time). HKDF is a thin wrapper. | Considered safe. |
| SHA-256 | BCL `System.Security.Cryptography.SHA256`. | Same. | Same as HKDF. | Considered safe. |
| RNG | BCL `System.Security.Cryptography.RandomNumberGenerator`. | Same. | Reads from the OS CSPRNG (`getrandom(2)` on Linux, `BCryptGenRandom` on Windows, `SecRandomCopyBytes` on macOS). | Considered safe. |

### What this means in practice

For an attacker model that does **not** include co-tenancy on the same
physical CPU and does **not** include physical proximity, the dominant
side-channel risk is wall-clock timing of ML-KEM-768 and ML-DSA-87. The PQF
wrapper makes those operations run in constant iteration, so a network
attacker observing decrypt latency learns the number of recipient slots (which
is already public from the file header) but not which one matched.

For an attacker model that **does** include co-tenancy or physical access,
PQF makes no claim. Cryptographic operations in this attacker model should
not run inside a managed runtime against keys whose compromise the operator
cannot accept; they should run in an HSM or a hardware enclave with
side-channel-hardened firmware. PQF is a file-format library, not a key
custody solution, and is not the right tool for that threat model.

---

## What is explicitly out of scope

The following are not, and will not be, claims of this implementation:

- Constant-time guarantees of BouncyCastle's ML-KEM-768 or ML-DSA-87 against
  power, EM, or microarchitectural side channels.
- Constant-time guarantees of any primitive after JIT compilation. RyuJIT's
  per-tier code generation is opaque to source-level reasoning.
- Resistance to fault injection, glitching, or physical tampering.
- Resistance to Spectre-class speculative-execution attacks against the host
  process.
- Resistance to memory-disclosure attacks (core dumps, hibernation files,
  swap, ptrace) that capture the process address space. `SecureZero.Clear`
  reduces the window but does not close it; managed-runtime garbage
  collection means transient copies of secret material may exist on the heap
  for unbounded time before collection.

If your threat model includes any of the above, do not rely on this
implementation in its current form.

---

## What would change this posture

The maintainers would consider a change of posture warranted only after at
least one of the following:

1. ~~The .NET BCL ships first-class `System.Security.Cryptography.MLKem` and
   `MLDsa` with documented side-channel claims, and PQF migrates to those
   APIs on the .NET version that ships them.~~ **Partially done.** As of
   PQF 0.4.x the [`BclCryptoProvider`](../src/PostQuantum.FileFormat/Crypto/BclCryptoProvider.cs)
   reflectively bridges to `System.Security.Cryptography.MLKem` and
   `MLDsa` when they are present and report `IsSupported = true` at
   runtime. The bridge does **not** itself improve the posture: what
   improves the posture is the platform crypto provider behind those
   types. Whether the platform claim is stronger than BouncyCastle's lack
   of claim depends on the host. PQF will continue to track the BCL
   surface as it stabilises and as Microsoft publishes side-channel
   guidance for these primitives.
2. An external cryptographer performs and publishes a side-channel review of
   BouncyCastle's ML-KEM-768 / ML-DSA-87 with a positive result on RyuJIT.
3. PQF gains a native-code provider (e.g. wrapping liboqs) with documented
   side-channel claims, and the maintainers can build, test, and ship that
   provider across the supported runtime matrix.

Until one of those happens, the posture stated in this document is the
posture of the implementation. Reviewers and integrators should treat it as
authoritative for what is *not* claimed, and as a starting point for their
own review of what *is* claimed.

---

## How to report a side-channel finding

A reproducible timing or microarchitectural finding against PQF's wrapper
code (i.e. the rows in the "What we control" table above) is in scope for
[SECURITY.md](../SECURITY.md) and should be reported through the private
GitHub Security Advisory channel.

A finding against an upstream primitive (BouncyCastle, BCL) should be
reported to that upstream first; the maintainers will track the upstream
issue and update this document and the affected wrapper code once a fix is
available.
