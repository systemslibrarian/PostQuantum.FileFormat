# PQF Implementation Checklist

**Derived from:** `spec/PQF-SPEC-v1.md` v0.3.1
**Purpose:** Exhaustive list of normative requirements, organized by
implementation surface. Every item traces back to a specific spec section.
**Status:** Companion document. Not normative — the spec is authoritative.
If this checklist and the spec disagree, the spec wins.

**How to use this document:**

- As an implementer: work through sections in order. Check off items as the
  corresponding code and tests are written. Every unchecked item is
  potential non-conformance.
- As a reviewer: use this as the PR review checklist. If a PR touches one
  of these areas without covering the relevant items, ask why.
- As a conformance auditor: every item represents a testable property. The
  test vector suite (when published) exercises each item.

**Legend:**

- 🔴 MUST / MUST NOT — refusal to conform if missing
- 🟡 SHOULD / SHOULD NOT — strong guidance, deviate only with documented reason
- ⚪ MAY — optional feature, conforming to implement or not

Total normative statements in spec v0.3.1: 66 MUST/SHOULD items.

---

## 1. CBOR encoding (spec §2.5)

### 1.1 Encoder obligations

- [ ] 🔴 Integers use the shortest form (§2.5 item 1)
- [ ] 🔴 Definite-length encoding for all items — no indefinite-length (§2.5 item 2)
- [ ] 🔴 Map keys sorted by byte-wise lexicographic order of their encoded form, length first then lex (§2.5 item 3)
- [ ] 🔴 No duplicate map keys emitted (§2.5 item 4)
- [ ] 🔴 Floating-point numbers never appear in output (§2.5 item 5)
- [ ] 🔴 Text strings use UTF-8 (§2.5 item 6)
- [ ] 🔴 Byte strings use native `bstr` major type 2 (no base64 wrapping) (§2.5 item 7)

### 1.2 Parser/validator obligations

- [ ] 🔴 Reader verifies header CBOR encoding is deterministic per RFC 8949 §4.2.2 (§2.5 "Determinism enforcement")
- [ ] 🔴 Implementation uses either: (a) parser that enforces deterministic encoding natively and rejects non-conforming input, OR (b) parser whose output is re-encoded and byte-for-byte compared with original (§2.5)
- [ ] 🔴 Permissive CBOR parsing is non-conforming (§2.5 "Permissive CBOR parsing...is non-conforming")
- [ ] 🔴 Reader rejects non-shortest integer encodings (§6.3 step 4)
- [ ] 🔴 Reader rejects indefinite-length items (§6.3 step 4)
- [ ] 🔴 Reader rejects duplicate map keys (§6.3 step 4)
- [ ] 🔴 Reader rejects floating-point values (§2.5, §6.3 step 4)
- [ ] 🔴 Reader rejects trailing bytes after top-level CBOR item

---

## 2. Header structure (spec §4)

### 2.1 Required fields

- [ ] 🔴 `alg` present; exact map structure (§4.2.1)
- [ ] 🔴 `alg.aead` equals `"aes-256-gcm-chunked"` exactly (§4.2.1)
- [ ] 🔴 `alg.combiner` equals `"pqf1-concat-extract-v1"` exactly (§4.2.1)
- [ ] 🔴 `alg.kdf` equals `"hkdf-sha256"` exactly (§4.2.1)
- [ ] 🔴 `alg.kem` equals `"x25519+ml-kem-1024"` exactly (§4.2.1)
- [ ] 🔴 `alg.sig` equals `"ed25519+ml-dsa-87"` exactly (§4.2.1)
- [ ] 🔴 `chunk_size` present; power of 2 in range [4096, 16777216] (§4.2)
- [ ] 🔴 `created` present; RFC 3339 UTC with `Z` suffix (§4.2)
- [ ] 🔴 Writer emits `created` in UTC only, not local time offsets (§4.2)
- [ ] 🔴 `file_id` present; exactly 16 bytes decoded (§4.2)
- [ ] 🔴 `recipients` present; non-empty array (§4.2)
- [ ] ⚪ `signer` present iff file is signed (§4.2)

### 2.2 Recipient block

- [ ] 🔴 `classical_epk`: exactly 32 bytes (§4.2.2)
- [ ] 🔴 `pqc_ct`: exactly 1568 bytes (§4.2.2)
- [ ] 🔴 `wrapped_dek`: exactly 48 bytes (§4.2.2)
- [ ] 🔴 `wrapped_dek_nonce`: exactly 12 bytes (§4.2.2)
- [ ] 🔴 Reader validates exact byte-string lengths and refuses on mismatch (§4.2.2)

### 2.3 Signer block

- [ ] 🔴 `classical_pub`: exactly 32 bytes (§4.2.3)
- [ ] 🔴 `pqc_pub`: exactly 2592 bytes (§4.2.3)

### 2.4 Extensibility (§4.3)

- [ ] 🔴 Reader refuses any unknown field at top level (§4.3)
- [ ] 🔴 Reader refuses any unknown field inside `alg` (§4.3)
- [ ] 🔴 Reader refuses any unknown field inside each recipient block (§4.3)
- [ ] 🔴 Reader refuses any unknown field inside `signer` (§4.3)

---

## 3. File layout (spec §3)

- [ ] 🔴 Magic `"PQF1"` at offset 0, 4 bytes ASCII (§3)
- [ ] 🔴 Version `0x0001` at offset 4, uint16 BE (§3)
- [ ] 🔴 Header length at offset 6, uint32 BE (§3)
- [ ] 🔴 Header length ≤ 1,048,576 bytes (1 MiB); readers reject larger (§3)
- [ ] 🔴 Header signature present iff `header.signer` non-null; exactly 4691 bytes when present (§3)
- [ ] 🔴 Footer exactly 20 bytes (§3, §5.5)
- [ ] 🔴 File signature present iff `header.signer` non-null; exactly 4691 bytes when present (§3)
- [ ] 🔴 When unsigned, signature fields omitted entirely (not placeholder zero-length) (§3 "Offset note")
- [ ] 🔴 Reader refuses file where signature presence disagrees with `header.signer` (§3)

---

## 4. Chunks (spec §5)

### 4.1 Chunk encoding

- [ ] 🔴 Chunk length: uint32 BE (§5.3)
- [ ] 🔴 Chunk flags: uint8 (§5.3)
- [ ] 🔴 Reserved flag bits (bits 1-7) zero on write (§5.3)
- [ ] 🔴 Reader refuses chunks with any reserved flag bit set (§5.3)
- [ ] 🔴 Reader verifies chunk length does not exceed remaining file bounds, accounting for 20-byte footer + optional 4691-byte file signature (§5.3 "Bounded chunk length")
- [ ] 🔴 Chunk ciphertext + 16-byte GCM tag follows flags byte (§5.3)

### 4.2 Per-chunk crypto

- [ ] 🔴 `chunk_key = HKDF-Expand(dek, info = "PQF1-chunk-v1" || i (8 bytes BE), L = 32)` (§5.2)
- [ ] 🔴 `chunk_nonce` is 12 bytes, all zero (§5.2)
- [ ] 🔴 `aad = file_id (16 bytes) || i (8 bytes BE) || is_final (1 byte)` (§5.2)
- [ ] 🔴 `is_final = 0x01` for last chunk, `0x00` otherwise (§5.2)
- [ ] 🔴 AES-256-GCM-Encrypt using chunk_key, chunk_nonce, plaintext_chunk, aad (§5.2)

### 4.3 Chunking constraints

- [ ] 🔴 Final chunk ≥ 1 byte unless file is empty (§5.1)
- [ ] 🔴 Empty file encoded as zero chunks (§5.1)

---

## 5. Footer (spec §5.5)

- [ ] 🔴 Footer bytes 0-3: magic `"PQFE"` (§5.5)
- [ ] 🔴 Footer bytes 4-11: total chunk count, uint64 BE (§5.5)
- [ ] 🔴 Footer bytes 12-19: total plaintext bytes, uint64 BE (§5.5)
- [ ] 🔴 Reader MUST compare `total_chunk_count` against observed chunks read; mismatch is fatal (§5.5 "Footer validation")
- [ ] 🔴 Reader MUST compare `total_plaintext_bytes` against observed plaintext sum; mismatch is fatal (§5.5 "Footer validation")
- [ ] 🔴 Footer covered by file signature when signed (§5.5, §6.2 step 9, §8.3)

---

## 6. Key derivation and combiner (spec §2.4)

- [ ] 🔴 `combined_ss = HKDF-Extract(salt, ikm)` where salt and ikm are exactly as specified (§2.4)
- [ ] 🔴 Salt = `"PQF1-combiner-v1" (16 bytes) || file_id (16 bytes) || recipient_index (4 bytes BE)` (§2.4)
- [ ] 🔴 IKM = `x25519_shared_secret (32 bytes) || mlkem_shared_secret (32 bytes)` (§2.4)
- [ ] 🔴 `kek = HKDF-Expand(combined_ss, info = "PQF1-kek-v1", L = 32)` (§2.4)

---

## 7. Encryption procedure (spec §6.2)

- [ ] 🔴 Generate random 32-byte DEK (§6.2 step 1)
- [ ] 🔴 Generate random 16-byte `file_id` (§6.2 step 2)
- [ ] 🔴 Per recipient: ephemeral X25519 keypair, fresh per recipient (§6.2 step 3a)
- [ ] 🔴 `ss_classical = X25519(esk_i, R_i.x25519_pk)` (§6.2 step 3b)
- [ ] 🔴 `(ss_pqc, ct_pqc) = MLKEM.Encap(R_i.mlkem_pk)` (§6.2 step 3c)
- [ ] 🔴 KEK derived per §2.4 with actual file_id and recipient_index = i (§6.2 step 3d)
- [ ] 🔴 Generate random 12-byte wrap_nonce per recipient (§6.2 step 3e)
- [ ] 🔴 `wrapped_dek = AES-256-GCM-Encrypt(KEK, wrap_nonce, DEK, aad = file_id)` (§6.2 step 3f)
- [ ] 🔴 Header encoded as deterministic CBOR (§6.2 step 4)
- [ ] 🔴 If signed: `ed25519_sig = Ed25519.Sign(S.ed25519_sk, header_bytes)` (§6.2 step 5a)
- [ ] 🔴 If signed: `mldsa_sig = ML-DSA-87.Sign(S.mldsa_sk, header_bytes)` (§6.2 step 5b)
- [ ] 🔴 If signed: `header_signature = ed25519_sig (64) || mldsa_sig (4627)` = 4691 bytes (§6.2 step 5c)
- [ ] 🔴 Running SHA-256 computed over on-disk chunk bytes in write order (§6.2 step 7)
- [ ] 🔴 Footer written with accurate chunk_count and plaintext_bytes (§6.2 step 8)
- [ ] 🔴 If signed: file_signature covers `file_id (16) || sha256_of_chunks (32) || footer (20)` = 4691 bytes hybrid signature (§6.2 step 9)

---

## 8. Decryption procedure (spec §6.3, §6.4)

### 8.1 Common validation (§6.3)

- [ ] 🔴 Magic validated as exactly `"PQF1"` (§6.3 step 2)
- [ ] 🔴 Version validated as exactly `0x0001` (§6.3 step 2)
- [ ] 🔴 Header length ≤ 1 MiB (§6.3 step 2)
- [ ] 🔴 Header parsed as deterministic CBOR; non-determinism refused (§6.3 step 4)
- [ ] 🔴 Duplicate keys refused (§6.3 step 4)
- [ ] 🔴 Unknown fields at any level refused (§6.3 step 4, §4.3)
- [ ] 🔴 Missing required fields refused (§6.3 step 4)
- [ ] 🔴 Field values outside declared ranges/sizes refused (§6.3 step 4)
- [ ] 🔴 `alg` fields exactly match v1 values (§6.3 step 5)
- [ ] 🔴 `chunk_size` power of 2 in [4096, 16777216] (§6.3 step 6)

### 8.2 Header signature verification (when signed)

- [ ] 🔴 Read exactly 4691 bytes header_signature (§6.3 step 7a)
- [ ] 🔴 Split: classical_sig = header_signature[0..64], pqc_sig = header_signature[64..4691] (§6.3 step 7b)
- [ ] 🔴 Verify Ed25519 half against signer.classical_pub (§6.3 step 7c)
- [ ] 🔴 Verify ML-DSA-87 half against signer.pqc_pub (§6.3 step 7d)
- [ ] 🔴 If EITHER verification fails, refuse (§6.3 step 7e)

### 8.3 Recipient trial

- [ ] 🔴 Try each recipient block in order (§6.3 step 8)
- [ ] 🔴 ML-KEM decap never short-circuits on "failure" — proceeds regardless (§6.3 step 8b)
- [ ] 🔴 KEK derived per §2.4 with recipient_index = i (§6.3 step 8c)
- [ ] 🔴 AES-GCM-Decrypt on wrapped_dek with aad = file_id (§6.3 step 8d)
- [ ] 🔴 If no recipient block succeeds, refuse: "not a recipient" (§6.3 step 8g)
- [ ] 🔴 All recipient blocks attempted even after one succeeds — constant time (§6.5)

### 8.4 Authenticated Mode (§6.4.1)

- [ ] 🔴 Plaintext not released until file signature verified (signed) or footer validated (unsigned) (§6.4.1)
- [ ] 🔴 Implementation MUST support Authenticated Mode (§6.4)
- [ ] 🔴 Footer bytes retained as read, used byte-identical in signature verification (§6.4.1 step 4-5)
- [ ] 🔴 Re-encoding parsed footer values for signature verification is non-conforming (§6.4.1 step 5)

### 8.5 Streaming Mode (§6.4.2)

- [ ] ⚪ Implementation MAY support Streaming Mode (§6.4)
- [ ] 🔴 If unsupported, caller requesting Streaming Mode gets an error, not silent fallback (§6.4)
- [ ] 🔴 On AEAD tag success, plaintext may be released (§6.4.2 step 2)
- [ ] 🔴 Footer count validation on read (§6.4.2 step 3)
- [ ] 🔴 File signature verification after all chunks read (§6.4.2 step 4)
- [ ] 🔴 Caller can reliably detect post-hoc authentication failure (§6.4.2 "Failure signaling")
- [ ] 🔴 Silent failure, log-only reporting non-conforming (§6.4.2 "Failure signaling")
- [ ] 🔴 Mechanism is impossible to overlook: exception that propagates, non-zero return that must be checked, or explicit Result type (§6.4.2)

---

## 9. Secret hygiene (spec §6.5, §6.6)

- [ ] 🔴 Non-matching recipient trial secrets discarded and zeroed (§6.5)
- [ ] 🔴 Intermediate secrets (shared secrets, DEKs, chunk keys, KEKs) zeroed after use (§6.6)
- [ ] 🟡 Private keys zeroed when identity disposed (§6.6)

---

## 10. Key formats (spec §7)

### 10.1 Canonical binary (§7.1)

- [ ] 🔴 Encryption public key: version byte 0x01 + X25519 pubkey (32) + ML-KEM-1024 pubkey (1568) = 1601 bytes (§7.1)
- [ ] 🔴 Signing public key: version byte 0x01 + Ed25519 pubkey (32) + ML-DSA-87 pubkey (2592) = 2625 bytes (§7.2)
- [ ] 🔴 Reader rejects wrong total length (§7.1, §7.2)
- [ ] 🔴 Reader rejects version byte not 0x01 (§7.1, §7.2)

### 10.2 PEM (§7.2)

- [ ] 🔴 Encryption public key label: `PQF PUBLIC KEY` (§7.2)
- [ ] 🔴 Signing public key label: `PQF SIGNING PUBLIC KEY` (§7.2)
- [ ] 🔴 Standard base64 with `=` padding, wrapped at 64 chars (§7.2)
- [ ] 🔴 Reader accepts LF or CRLF line endings (§7.2)
- [ ] 🔴 Reader accepts ASCII whitespace between header/body/footer (§7.2)
- [ ] 🔴 Writer emits exact label strings (§7.2)

### 10.3 Fingerprint (§7.3)

- [ ] 🔴 Fingerprint = SHA-256 over canonical binary public key (§7.3)
- [ ] 🔴 Fingerprint length always 32 bytes (§7.3)
- [ ] 🔴 Full hex: 64 lowercase hex characters (§7.3)
- [ ] 🔴 Short form: first 8 bytes = 16 hex characters (§7.3)
- [ ] 🔴 Fingerprints MUST NOT be used as cryptographic identifiers (§7.3 "CRITICAL RULE")
- [ ] 🔴 Fingerprints MUST NOT be used as database primary keys (§7.3)
- [ ] 🔴 Fingerprints MUST NOT be used in automated identity matching (§7.3)

---

## 11. Fail-closed master list (spec §8.4)

Readers MUST refuse under all of the following. This section duplicates items
from earlier sections intentionally — it is the master rejection list used for
testing.

- [ ] 🔴 Magic mismatch
- [ ] 🔴 Version mismatch
- [ ] 🔴 Header length > 1 MiB
- [ ] 🔴 Non-deterministic CBOR encoding
- [ ] 🔴 Unknown field at any header level
- [ ] 🔴 Missing required field
- [ ] 🔴 Algorithm identifier mismatch
- [ ] 🔴 `chunk_size` invalid
- [ ] 🔴 `created` not in RFC 3339 UTC "Z" form
- [ ] 🔴 Empty `recipients` array
- [ ] 🔴 Binary field length mismatch
- [ ] 🔴 Identity matches no recipient block
- [ ] 🔴 Signature verification failure (either hybrid half)
- [ ] 🔴 AEAD tag failure (wrap, chunk, anywhere)
- [ ] 🔴 Footer chunk count mismatch
- [ ] 🔴 Footer plaintext bytes mismatch
- [ ] 🔴 Footer magic missing or incorrect
- [ ] 🔴 Reserved chunk flag bits set
- [ ] 🔴 Chunk length exceeds remaining file bounds
- [ ] 🔴 Truncation (EOF before expected end)
- [ ] 🔴 Trailing data after expected EOF

---

## 12. Conformance class coverage (spec §9)

### 12.1 Conforming writer (§9.1)

- [ ] 🔴 Produces files matching §3 byte layout
- [ ] 🔴 Encodes header as deterministic CBOR per §2.5
- [ ] 🔴 Populates all required header fields with valid values
- [ ] 🔴 Uses v1 algorithms exactly as specified in §2
- [ ] 🔴 Uses cryptographically secure randomness for DEK, file_id, ephemeral keys, wrap nonces
- [ ] 🔴 Writes footer with accurate chunk_count and plaintext_bytes
- [ ] 🔴 When signing, writes signatures per §6.2 step 9 covering file_id + chunk hash + footer
- [ ] 🔴 Zeroes intermediate secrets per §6.6

### 12.2 Conforming reader (Authenticated Mode) (§9.2)

- [ ] 🔴 Implements all refusal conditions in §8.4
- [ ] 🔴 Verifies file signature (when present) before releasing plaintext
- [ ] 🔴 Validates footer before releasing plaintext
- [ ] 🔴 Attempts all recipient blocks for constant-time trial (§6.5)
- [ ] 🔴 Does not short-circuit on ML-KEM decap "failure" (§6.3 step 8b)
- [ ] 🔴 Rejects unknown header fields at every level

### 12.3 Conforming reader (Streaming Mode) (§9.3)

- [ ] ⚪ Implementation may skip this class entirely
- [ ] 🔴 If implemented: meets §9.2 except pre-release buffering
- [ ] 🔴 If implemented: signals post-hoc failure to caller
- [ ] 🔴 If implemented: does not silently discard post-hoc verification failures

### 12.4 Conforming verifier (§9.4)

- [ ] 🔴 Verifies both classical and post-quantum signature halves
- [ ] 🔴 Refuses if either half fails, regardless of the other
- [ ] 🔴 Does not accept truncated or extended signatures (fixed 4691-byte length)

### 12.5 Conforming key format implementation (§9.5)

- [ ] 🔴 Implements canonical binary format (§7.1)
- [ ] 🟡 Implements PEM format (§7.2)
- [ ] ⚪ Implements fingerprints (§7.3)
- [ ] 🔴 If fingerprints implemented: does not use them as cryptographic identifiers

---

## Phase-to-checklist mapping

Rough guide for which implementation phase should cover which checklist sections:

- **Phase 1** (foundations, no crypto): Sections 1, 10
- **Phase 2** (header and file layout): Sections 2, 3, 11 (partial)
- **Phase 3** (crypto core): Sections 4, 6, 7, 9
- **Phase 4** (decryption modes): Section 8, 11 (completion)
- **Phase 5** (conformance testing): Section 12

Ideally by the end of Phase 5, every box is checked or explicitly marked
"not applicable to this implementation."

---

## Document history

| Version | Date | Notes |
|---|---|---|
| 0.1.0 | 2026-04-21 | Initial extraction from spec v0.3.1 |