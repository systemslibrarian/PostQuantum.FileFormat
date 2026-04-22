# Gemini Notes: Repository Review

**Date:** 2026-04-22

## High-Level Assessment
This repository is exceptionally well-structured for an experimental cryptographic project. It avoids the most common pitfall of early crypto projects by not pretending to be more secure or mature than it actually is. The discipline of being "spec-first," enforcing deterministic CBOR, and documenting the exact side-channel limitations of dependencies shows a high level of engineering maturity.

## Areas for Improvement (in order of priority)

### 1. Architectural Limit: Streaming Validation
Currently, the parser validates the entire byte array in memory using `int`-indexed offsets. While the wire format logically supports larger files through `uint64` lengths, the reference implementation caps file sizes at available RAM. 
**Next Step:** Implement a true streaming parser that validates chunks on the fly with a sliding window, buffering only the footer and signatures. This is the biggest pure-engineering hurdle left.

### 2. Cryptographic Credibility: Lack of External Audit
The metadata and documentation are excellent, but the core cryptographic constructions—specifically the `HKDF` combiner (`"PQF1-combiner-v1"`) and the chunked AEAD/AAD binding—haven't been formally proven or externally audited.
**Next Step:** Commission or request a targeted review from a professional cryptographer specifically focusing on the hybrid KEM combiner and the signature coverage domain separation.

### 3. Implementation Risk: BouncyCastle & Side Channels
As documented in `SIDE-CHANNEL-POSTURE.md`, relying on managed C# BouncyCastle for ML-KEM-1024 and ML-DSA-87 means there are no firm constant-time execution guarantees at the CPU level due to JIT compilation and garbage collection.
**Next Step:** Once the format is stable, create an alternative crypto provider that binds to a native, constant-time library (like `liboqs`) via P/Invoke, or migrate entirely to .NET's native BCL implementations once they officially support ML-KEM/ML-DSA.

### 4. Format Robustness: Single-Language Bias
Writing the spec and the first implementation simultaneously in .NET creates a risk that the spec replies on implicit behaviors of the .NET BCL or the specific CBOR library in use.
**Next Step:** Build a minimal "read-only" implementation in a second language (like Rust or Go) using completely different cryptography and CBOR libraries. Running the test vectors through a foreign tech stack is the best way to prove the spec is truly language-agnostic.

### 5. Resolving the "Open Questions"
The design rationale explicitly lists unresolved questions, like whether to add explicit `"PQF1-header-sig-v1"` domain separation prefixes and whether the footer should be AEAD-bound on unsigned files.
**Next Step:** These are fantastic questions, but they represent wire-format changes. The project should force a decision on these (adopting both for strictness is recommended) before locking in `v1.0.0` to avoid needing a `PQF2` magic byte in the near future.