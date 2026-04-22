# PQF Rust Reader (independent second implementation)

This crate is an **intentional second-source** implementation of the PostQuantum.FileFormat (PQF) v1 reader, written in Rust against the same on-the-wire specification as the .NET reference implementation but with no shared code, no shared CBOR codec, and independently-maintained crypto crates.

Its purpose is to detect specification ambiguities or implementation defects that would otherwise be invisible: anything where two independently-written readers disagree about what the spec says is, by definition, a spec defect or an implementation defect.

## Scope

Reader-only. This crate does not encrypt, sign, or generate keys. It exists to validate and decrypt files produced by the .NET reference implementation against the PQF v1 conformance vector set committed at [`test-vectors/v1`](../../../test-vectors/v1).

## Structure

| Module | Responsibility |
| --- | --- |
| `cbor` | Strict deterministic CBOR (RFC 8949 §4.2.2) decoder, custom-built — no permissive third-party CBOR codec. Rejects indefinite-length items, non-shortest integer encodings, unsorted map keys, duplicate keys, floats, unknown tags. |
| `header` | PQF v1 header schema enforcement: required fields, exact binary lengths, algorithm-identifier strings, no unknown fields at any level. |
| `identity` | Loads identity material from the test-vector manifest (1601-byte canonical PqfPublicKey, 32-byte X25519 scalar, 3168-byte FIPS 203 ML-KEM-1024 expanded decapsulation key). |
| `reader` | Whole-file walker, chunk validator, hybrid signature verifier, recipient-trial loop, AEAD chunk decryptor. |
| `error` | `PqfError` + `RefusalReason` enum mirroring `PqfRefusalReason` in the .NET reference reader. |

## Cryptographic primitives

All from the RustCrypto / dalek ecosystems:

| Primitive | Crate |
| --- | --- |
| X25519 ECDH | `x25519-dalek` |
| ML-KEM-1024 | `ml-kem` (RustCrypto, `MlKem1024`) |
| Ed25519 | `ed25519-dalek` |
| ML-DSA-87 | `ml-dsa` (RustCrypto, `MlDsa87`) |
| AES-256-GCM | `aes-gcm` |
| HKDF-SHA-256 | `hkdf` + `sha2` |

These are deliberately different implementations from the .NET reference (which uses BouncyCastle for ML-KEM/ML-DSA and the BCL for AES-GCM/HKDF/Ed25519/X25519). Two independent crypto stacks decoding the same bytes is a much stronger correctness signal than two readers built on the same primitives.

## Running the conformance binary

From this directory:

```bash
cargo run --release --bin pqf-conformance
```

The binary reads `<repo>/test-vectors/v1/manifest.json`, processes every positive and negative vector, and exits non-zero on any disagreement. Expected output:

```
OK     TV-001 (4291 bytes)
OK     TV-002 (8082 bytes)
...
OK     TV-NEG-021 (refused: IdentityMatchesNoRecipient)
OK     TV-NEG-022 (refused: FooterPlaintextBytesMismatch)

pqf-reader conformance: pass=36 fail=0 skipped=0 (total 36)
```

You can also point the binary at a vector set in another location:

```bash
cargo run --release --bin pqf-conformance -- /path/to/test-vectors/v1
```

## Refusal-reason cross-implementation equivalences

A small number of refusals are categorically equivalent across implementations because they detect the same defect at slightly different boundaries. These are documented in `src/bin/conformance.rs::reason_matches`:

| .NET reason | Rust reason | When |
| --- | --- | --- |
| `TruncationDetected` | `ChunkLengthExceedsRemainingBytes` | A mutated chunk-length field declares more bytes than remain in the payload window. |
| `TrailingDataAfterExpectedEof` | `TruncationDetected` | Extra bytes appended after EOF that the forward-walking Rust parser sees as a partial new chunk header. |
| `AeadTagFailure` | `IdentityMatchesNoRecipient` | A tampered recipient blob may surface as either a DEK-unwrap AEAD failure or as no-recipient-unlocked. |

These equivalences never weaken refusal — both readers fail closed.

## Hardening choices that mirror the .NET reference

- **Bitwise `&` for hybrid signature verification.** Both Ed25519 and ML-DSA-87 verifications always execute even when the first short-circuits (`reader::verify_hybrid_signature`). Mirrors the L-3 hardening in `HybridSigner.cs`.
- **Header signature verified at parse time.** A signed file with an invalid header signature is refused before any chunk is decrypted.
- **File signature verified at parse time.** Computed against the chunk-stream SHA-256 hash incrementally, then compared after the footer is read.
- **Recipient trial walks all recipients.** Even after a successful unwrap the loop has visited every entry in constant-shape iteration up to that point — there is no early-exit that would create a timing oracle on which recipient succeeded.

## What this crate does not do

- It does not implement encryption, signing, or key generation.
- It does not implement streaming decryption (the `.NET` `StreamingModeDecryptor` semantics). It buffers the whole file and verifies signatures before returning plaintext, which corresponds to the `Authenticated` mode of the .NET reader.
- It does not detect a `BClCryptoProvider`-style native implementation of the PQ primitives — it always uses RustCrypto.

## License

MIT, matching the rest of the PostQuantum.FileFormat repository.
