# Reference implementation (Phase 1 complete)

This directory contains the .NET reference implementation of the PQF v1 Phase 1
foundations in the `PostQuantum.FileFormat` library (targeting `net8.0`).

## What Phase 1 ships

1. Deterministic CBOR encoder and strict validator (spec section 2.5)
2. Canonical binary encryption/signing public key format types (spec section 7.1)
3. PEM armoring and dearmoring for public keys (spec section 7.2)
4. Fingerprint computation and formatting helpers (spec section 7.3)
5. Unit and integration tests for the full Phase 1 surface

## What Phase 2 adds

1. HKDF combiner and KEK derivation (spec section 2.4)
2. DEK wrapping and recipient processing (spec section 6.2)
3. Chunked payload encryption/decryption with footer validation (spec section 5)
4. Hybrid header/file signature operations (spec section 6.2, section 6.4)
5. Full file read/write workflows for authenticated and streaming modes

The `pqf` CLI tool remains in the sibling `cli` directory and is out of scope
for Phase 1.

See the [specification](../spec/PQF-SPEC-v1.md) for authoritative detail.
