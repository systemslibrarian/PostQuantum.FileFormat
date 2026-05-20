# `pqf-writer` — Independent Rust writer (scaffold)

A second-source Rust implementation of the PQF v1 **writer** path, to
complement the existing reader in `impl/rust/pqf-reader`.

## Status

**Scaffold.** The pieces that are implemented:

- Deterministic CBOR encoding for the header (RFC 8949 §4.2.2),
  including the byte-lexicographic key ordering required by the spec.
- The header builder, validating chunk-size constraints and recipient
  field lengths at the wire layer.
- Public API surface for `encrypt_to_bytes` (currently returns
  `NotYetImplemented`).

The pieces that are TODO and constitute the next contribution surface:

1. **X25519 ephemeral keygen + ECDH** with the recipient's classical pub.
2. **ML-KEM-1024 encapsulation** against the recipient's PQ pub.
3. **HKDF combiner** producing the per-recipient KEK
   (`pqf1-concat-extract-v1`, spec §2.4).
4. **AES-GCM wrap** of the per-file DEK under each recipient's KEK.
5. **Chunked AEAD** of the plaintext with per-chunk HKDF-derived keys.
6. **Footer** construction.
7. **Hybrid signing** (Ed25519 + ML-DSA-87), including the deterministic
   variant the .NET writer already supports.

## Why scaffold instead of complete?

Implementing crypto code without a working oracle to validate against
is how subtle bugs get baked in. The .NET reference writer is the
oracle. The deterministic-CBOR pieces I've implemented here have an
obvious test: encode a header in this crate, encode the same header
in .NET, diff the bytes. That test will go in the cross-impl
conformance gate once it's wired up.

The crypto operations themselves are routine — they wrap RustCrypto
crates we already depend on for the reader — but each one wants a
focused PR with its own conformance test.

## Building

```bash
cargo build --release -p pqf-writer
```

This passes today; it does not yet do useful work.
