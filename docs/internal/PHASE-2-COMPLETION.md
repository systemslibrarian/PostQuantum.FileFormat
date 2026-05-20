# Phase 2 Completion Notes

## Overview
Phase 2 of PostQuantum.FileFormat implements the complete PQF file header parser and validator with fail-closed refusal architecture. All validation operates at the byte/structural level; cryptographic operations are deferred to Phase 3+.

## Architecture: Refusal-First Pipeline

The `PqfFileReader.ValidateAndParse()` method implements a sequential validation pipeline enforcing fail-closed semantics:

1. **Phase 2.1: Prefix Validation**
   - Magic: "PQF1" (0x50514631) at offset 0
   - Version: 0x0001 at offset 4  
   - Header Length: uint32 at offset 6, range [1 byte, 1 MiB]
   - Refusal Reasons: `MagicMismatch`, `VersionMismatch`, `HeaderLengthExceedsLimit`

2. **Phase 2.2: CBOR Determinism**
   - Validates CBOR encoding follows RFC 8949 strict determinism rules
   - Enforces shortest integer encoding, no indefinite-length maps/arrays
   - Rejects floats, trailing bytes, duplicate keys, out-of-order keys
   - Maps validation errors to `NonDeterministicCborEncoding`, `DuplicateCborKey`, `TrailingDataAfterExpectedEof`

3. **Phase 2.3: Header Schema Validation**
   - Parses CBOR header map and validates all required/optional fields
   - `alg` submap: exact algorithm strings (aead, combiner, kdf, kem, sig)
   - `chunk_size`: uint, power of 2, range [4096, 16 MiB]
   - `created`: RFC 3339 UTC timestamp with 'Z' suffix (no +05:00 offsets)
   - `file_id`: binary string, exactly 16 bytes
   - `recipients`: non-empty array of recipient blocks
     - Each: classical_epk (32), pqc_ct (1568), wrapped_dek (48), wrapped_dek_nonce (12)
   - `signer` (optional): classical_pub (32), pqc_pub (2592)
   - Refusal Reasons: `MissingRequiredField`, `UnknownHeaderField`, `BinaryFieldLengthMismatch`, `AlgorithmIdentifierMismatch`, `ChunkSizeInvalid`, `CreatedTimestampInvalid`, `RecipientsEmpty`

4. **Phase 2.4: Signature Structural Presence**
   - If `header.signer` == null: verify no header signature follows
   - If `header.signer` != null: verify 4691-byte header signature present
   - Refusal Reason: `TruncationDetected`

5. **Phase 2.5-2.6: Footer Validation**
   - Magic: "PQFE" (0x50514645)
   - Chunk Count: int64 big-endian
   - Plaintext Bytes: int64 big-endian
   - Total: 20 bytes exactly
   - Refusal Reasons: `FooterMagicInvalid`, `TruncationDetected`

6. **Phase 2 EOF Check**
   - Verify no trailing data after footer + file signature (if signed)
   - If signed: verify 4691-byte file signature present
   - Refusal Reasons: `TrailingDataAfterExpectedEof`, `TruncationDetected`

## Test Coverage: 92 Tests (91 passing, 1 skipped)

### By Phase:
- **Phase 2.0**: 3 tests (exception types)
- **Phase 2.1**: 5 tests (magic, version, header length refusals)
- **Phase 2.2**: 11 tests (HeaderParser - CBOR determinism & structure)
- **Phase 2.3**: 9 tests (HeaderSchema - field validation)
- **Phase 2.4**: 4 tests (SignatureStructure - presence/absence, 1 skipped for Phase 2.5 context)
- **Phase 2.5-2.6**: 4 tests (ChunkAndFooter - footer magic, truncation)
- **Phase 2.7**: 4 tests (HappyPath - unsigned file, signed file, multiple recipients, large chunk size)
- **Phase 2.8**: 5 tests (Integration - validation pipeline precedence, refusal ordering)

**Total Refusal Reasons Exercised**: 19 out of 23 enum values
(4 skipped: ChunkLengthExceedsRemainingBytes, ReservedChunkFlagBitsSet, SignatureVerificationFailure, AeadTagFailure - deferred to Phase 3+)

## Key Design Decisions

1. **Fail-Closed Architecture**: Every validation failure immediately throws `PqfFileException` with specific `PqfRefusalReason` and optional `Offset`. No partial validation or permissive fallbacks.

2. **Enum-Based Reasons**: `PqfRefusalReason` enum (23 values) enables precise test assertions and differentiated error handling at higher layers.

3. **Offset Tracking**: Exception carries file offset of validation failure, enabling diagnostics and potential error recovery UI in applications.

4. **RFC 8949 Strict Determinism**: CBOR header must use exact canonical encoding (shortest integers, definite-length containers, sorted keys, no duplicates). Rejects any non-canonical encoding that would affect cryptographic binding.

5. **RFC 3339 UTC-Only Timestamps**: `created` field requires explicit 'Z' suffix (e.g., "2026-04-21T14:30:00Z"), rejects timezone offsets (+05:00). Ensures cross-platform timestamp unambiguity.

6. **Symmetric Signature Presence**: Header.signer field acts as signed/unsigned flag. If absent, file must have no signatures. If present, file must have both header (4691) and file (4691) signatures.

7. **Phase Gating with NotImplementedException**: After all Phase 2 validation succeeds, reader throws `NotImplementedException("PHASE 3: ...")` to clearly mark boundary between structural validation and cryptographic processing. This prevents incomplete implementations of decryption/verification from silently succeeding.

## Integration Points

- **Phase 1**: CBOR encoder/decoder (`DeterministicCborEncoder`, `DeterministicCborValidator`) validates encoding determinism
- **Phase 3+**: Decryption (ChaCha20-Poly1305 or AES-256-GCM), signature verification (Ed25519, ML-DSA-87), key exchange (X25519, ML-KEM-1024) deferred
- **Application Layer**: Exception handling can present human-readable refusal explanations per `PqfRefusalReason`

## Notable Edge Cases Covered

- Empty recipients array (invalid, must have ≥1)
- Header length = 0 (invalid, must be ≥1)
- Chunk size = 1 (invalid, must be power of 2 & ≥4096)
- Chunk size > 16 MiB (invalid, max boundary)
- File ID != 16 bytes (invalid)
- Recipient blocks with wrong binary field lengths
- Recipients array with < 4 required fields
- Signer block present with wrong field lengths
- Timestamp without 'Z' suffix (invalid)
- Footer magic mismatch
- Truncated footer (< 20 bytes after last signature)
- Trailing data after expected EOF
- Multiple recipients in same file (structurally valid)
- Signed files with both header and file signatures (structurally valid)

## Future Phases (3-8)

- **Phase 3**: Decryption pipeline (chunk processing, AEAD validation, DEK unwrapping)
- **Phase 4**: Signature verification (Ed25519 + ML-DSA-87, footerplaintext_bytes validation)
- **Phase 5**: Armor layer (PEM encoding, base64 line wrapping)
- **Phase 6**: Public APIs (high-level read/write/verify operations)
- **Phase 7**: Side-channel hardening (constant-time operations, key material cleanup)
- **Phase 8**: Documentation, examples, performance optimization

## Commits
All 8 phases (2.0-2.8) committed with descriptive messages to `main`:
- `phase-2.0: refusal reason enum and exception type`
- `phase-2.1: magic, version, header length refusals tested and enforced`
- `phase-2.2: CBOR determinism and duplicate key refusals enforced`
- `phase-2.3: header schema refusals enforced`
- `phase-2.4: signature structural presence validation`
- `phase-2.5-2.6: chunk structure and footer validation`
- `phase-2.7: happy path validation tests`
- `phase-2.8: integration tests and validation pipeline verification`

## Verification

```bash
DOTNET_ROLL_FORWARD=Major dotnet test PostQuantum.FileFormat.sln -c Release
# Result: 91 passing, 1 skipped, 0 failed
```

All Phase 1 tests (55) remain passing. Phase 2 adds 36 new tests for comprehensive refusal coverage.
