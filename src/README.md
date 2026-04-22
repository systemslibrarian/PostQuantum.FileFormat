# Reference implementation (coming)

This directory will contain the reference .NET implementation of PQF as the
`PostQuantum.FileFormat` NuGet package.

**First code to be written:**

1. Deterministic CBOR encoder (per spec §2.5)
2. Canonical binary public key format round-trip (per spec §7.1)
3. Fingerprint computation (per spec §7.3)
4. PEM armoring round-trip (per spec §7.2)

Only after these foundations pass their tests should cryptographic operations
begin to be implemented, in this order:

5. HKDF-SHA-256 combiner (per spec §2.4)
6. Per-recipient KEK derivation and DEK wrapping (per spec §6.2)
7. Chunked AEAD payload encryption (per spec §5.2)
8. Hybrid signatures (per spec §6.2 step 9)
9. Authenticated Mode decryption (per spec §6.4.1)
10. Streaming Mode decryption (per spec §6.4.2)

The `pqf` CLI tool lives in a sibling directory (`/cli/`).

See the [specification](../spec/PQF-SPEC-v1.md) for authoritative detail.
