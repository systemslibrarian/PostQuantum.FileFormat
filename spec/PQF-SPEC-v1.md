# PQF File Format — Specification, Version 1

**Status:** DRAFT / EXPERIMENTAL — do not use to protect irreplaceable data.
**Document version:** 0.6.0 (2026-05-30)
**Editor:** Paul Clark <paul@systemslibrarian.dev>
**License:** MIT

> *"So whether you eat or drink or whatever you do, do it all for the glory of God."* — 1 Corinthians 10:31

---

## Change log

**0.6.0 (2026-05-30)** — Hybrid KEM cut over from PQF's in-house
HKDF-bind-then-extract combiner (`pqf1-bind-extract-v1`, the 0.5
construction) to **X-Wing** (draft-connolly-cfrg-xwing-kem). This is a
wire-incompatible break from 0.5 (and from 0.3.x); every previously
published v1 test vector is invalidated. The bind-extract combiner that
0.5 introduced — itself a hardening of the older `pqf1-concat-extract-v1`
in response to review finding F2 — was still a PQF-author construction
without external security proofs; 0.6 removes it entirely in favor of
the standardized X-Wing combiner. Changes:

- §2.1 KEM: ML-KEM-1024 → **ML-KEM-768** (Category 3). X-Wing is defined
  for ML-KEM-768; staying on -1024 would require a non-standard variant
  combiner and defeat the purpose of adopting X-Wing.
- §2.4 Combiner: the PQF in-house `pqf1-bind-extract-v1` HKDF combiner
  is **removed**. KEM-level shared-secret derivation is now
  `SHA3-256( "\.//^\" || ss_M || ss_X || ct_X || pk_X )` exactly as
  specified by draft-connolly-cfrg-xwing-kem.
- §4.2.1 `alg.combiner` exact-match value: `"pqf1-bind-extract-v1"`
  → `"x-wing"`. `alg.kem` exact-match value:
  `"x25519+ml-kem-1024"` → `"x25519+ml-kem-768"`.
- §4.2.2 `pqc_ct` byte-string size: 1568 → **1088** (ML-KEM-768 ciphertext).
- §7.1 canonical encryption public-key total length: 1601 → **1217**
  bytes (version byte + 32 X25519 + 1184 ML-KEM-768).
- §2.4 / §8.7 Per-recipient binding migrates from the (now-deleted)
  HKDF salt slot into the DEK-wrap AEAD's associated data:
  `aad = file_id (16) || recipient_index (uint32 BE)`. Cross-recipient
  isolation and per-file binding are preserved at the AEAD layer.
- The old §13 caveats "No formal security proof" and "combiner rationale
  wording" are obsolete for the KEM combiner: X-Wing has IND-CCA proofs
  in ROM/QROM (Barbosa et al., 2024).
- File format version stays **v1** (magic `PQF1`, version uint16
  `0x0001`); only the alg-map exact-match values and the recipient
  byte-string sizes change. Pre-1.0.0 §10.4 freeze does not yet apply.
- The 0.5 hardening that signed-file readers gained (signature domain
  separation: `PQF1-header-sig-v1` / `PQF1-file-sig-v1`) is **preserved**
  unchanged; only the KEM combiner is rebuilt.

**0.5.0 (2026-05-30)** — Bind-extract combiner + signature domain
separation. The combiner's HKDF-Extract IKM now folds `classical_epk`
and `pqc_ct` alongside the two shared secrets, binding the KEK to the
exact KEM transcript (`pqf1-concat-extract-v1` → `pqf1-bind-extract-v1`).
Header and file signatures gained disjoint domain prefixes
`PQF1-header-sig-v1` / `PQF1-file-sig-v1`. Wire layout unchanged;
only the bytes fed to the KDF and signer changed. *Superseded by
0.6.0 on the same day; the 0.5 combiner is the one 0.6 X-Wing
deletes.*

**0.3.1 (2026-04-21)** — Polishing pass following ChatGPT v0.3.0 review. Six
tightening fixes, no design changes:

- §2.5: CBOR determinism enforcement now explicitly normative, with two
  acceptable implementation strategies named.
- §3: 1 MiB header length limit now justified (DoS prevention + 100-recipient
  comfort margin).
- §5.3: Chunk length MUST be bounded against remaining file bytes.
- §6.4.1 / §6.4.2: Footer bytes used in signature verification MUST be
  byte-identical to bytes read from file (no re-encoding).
- §6.4.2: Streaming Mode post-hoc failure signaling tightened — silent or
  log-only failure is now explicitly non-conforming.
- §8.4: Added `created` malformed and chunk-length-overflow to fail-closed
  refusal list.

**0.3.0 (2026-04-21)** — Major restructure following external review. Changes:

- Header encoding switched from canonical JSON to deterministic CBOR (RFC 8949 §4.2.2).
- Unknown top-level header fields now rejected (extensibility contradiction resolved).
- Authenticated and Streaming processing modes promoted to normative.
- Public key format split into three representations: canonical binary, PEM-armored, and fingerprint.
- Footer restructured to carry chunk count and plaintext byte count.
- File signature coverage explicitly includes footer fields.
- New §9 Conformance section.
- New §10 Versioning and Evolution section.
- New §11 Threat Model section.
- Implementation-specific references moved to Appendix A.
- Combiner rationale wording tightened to avoid implying formal proof.
- Recipient privacy phrasing tightened.
- New §8.8 on deniability semantics from ML-KEM implicit rejection.

**0.2.0 (2026-04-21)** — Grok review incorporated; canonical JSON tightened; fixed signature lengths; test vector format added.

**0.1.0 (2026-04-21)** — Initial DRAFT.

---

## 1. Introduction

### 1.1 Purpose

PQF ("Post-Quantum File") is a file format for encrypting data at rest to one
or more recipients, using hybrid post-quantum cryptography. It is designed for
long-term archival of files that must remain confidential against both
classical and quantum adversaries.

PQF is **not** a TLS replacement, a messaging protocol, or a disk encryption
scheme. It is a single-file container analogous to `age`, `gpg`, or PKCS #7
enveloped data, but hybrid post-quantum by default.

### 1.2 Design goals

1. **Hybrid post-quantum by default.** Every confidentiality operation combines
   a classical KEM with a post-quantum KEM. Every signature combines a
   classical signature with a post-quantum signature. A break in either
   family alone does not compromise the file.
2. **Versioned and frozen.** The on-disk byte format is precisely defined,
   version-tagged from byte 0, and frozen for each version. Readers MUST
   refuse unknown versions rather than attempt to parse them.
3. **Streaming-safe.** Encryption and decryption operate on streams with
   bounded memory.
4. **Multi-recipient.** A single file can be encrypted to many recipients
   without re-encrypting the payload.
5. **Fail-closed.** Unknown algorithms, malformed headers, missing fields,
   invalid signatures, and integrity failures all result in refusal.
6. **Interoperable.** The specification is complete enough that an
   independent implementation can read and write files produced by any
   conforming implementation.

### 1.3 Non-goals

- Backward compatibility with any existing format (age, PGP, CMS)
- Password-based encryption (deferred)
- Hardware token / HSM support (deferred)
- Network transport, TLS integration, certificate formats
- Multi-file archives
- Forward secrecy in the messaging sense
- Recipient anonymity against strong metadata analysis

### 1.4 Requirements language

The keywords MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY in this document are
to be interpreted as described in RFC 2119 and RFC 8174.

### 1.5 Terminology

| Term | Meaning |
|---|---|
| KEM | Key Encapsulation Mechanism |
| AEAD | Authenticated Encryption with Associated Data |
| DEK | Data Encryption Key — symmetric key encrypting the payload |
| KEK | Key Encryption Key — per-recipient key wrapping the DEK |
| Recipient | A party who can decrypt the file, identified by a hybrid public key |
| Identity | A hybrid private key that allows decryption as a recipient |
| Hybrid | A construction combining a classical and a post-quantum primitive such that security holds if at least one remains unbroken |
| Combiner | A construction producing a single shared secret from two KEM outputs |
| Fingerprint | A short hash over a canonical public key, for human verification only |

---

## 2. Cryptographic primitives (v1)

Version 1 uses exactly the following primitives. Readers that do not support
all of them MUST refuse to process version 1 files.

### 2.1 Key encapsulation

Hybrid KEM: **X-Wing** (X25519 + ML-KEM-768), per
draft-connolly-cfrg-xwing-kem.

- **X25519:** RFC 7748. Public key: 32 bytes. "Ciphertext" (ephemeral
  public key): 32 bytes. Shared secret: 32 bytes.
- **ML-KEM-768:** FIPS 203. NIST Category 3. Public key: 1184 bytes.
  Ciphertext: 1088 bytes. Shared secret: 32 bytes.

X-Wing combines the two into a 32-byte hybrid shared secret using a
single SHA-3-256 invocation that binds both KEM shared secrets, the
X25519 ephemeral public key, and the recipient's X25519 long-term public
key (§2.4). The construction has IND-CCA proofs in the ROM and QROM
(Barbosa et al., 2024).

Implementations of v1 0.6.0 are wire-incompatible with v1 0.5.x and earlier.

### 2.2 Signatures

Hybrid signature: **Ed25519 + ML-DSA-87**

- **Ed25519:** RFC 8032. Public key: 32 bytes. Signature: 64 bytes.
- **ML-DSA-87:** FIPS 204. NIST Category 5. Public key: 2592 bytes. Signature: 4627 bytes.

**Hybrid signature wire format:** `ed25519_sig (64 bytes) || mldsa_sig (4627 bytes)`. Total: **4691 bytes, fixed**.

Signatures are OPTIONAL per file. Processing mode semantics (§6.4) apply.

### 2.3 Symmetric encryption

**AES-256-GCM**, chunked (§5).

### 2.4 KEM combiner and per-recipient binding

The hybrid KEM shared secret (the recipient's KEK) is derived by the
**X-Wing combiner** per draft-connolly-cfrg-xwing-kem:

```
KEK = SHA3-256( XWING_LABEL || ss_M || ss_X || ct_X || pk_X )
```

where:

- `XWING_LABEL` is the 6 bytes `5C 2E 2F 2F 5E 5C` (the ASCII art
  "\.//^\"). Implementations MUST use this exact byte sequence. It is
  NOT the ASCII string "X-Wing".
- `ss_M` is the 32-byte ML-KEM-768 shared secret.
- `ss_X` is the 32-byte X25519 shared secret.
- `ct_X` is the 32-byte X25519 ephemeral public key (carried on the wire
  as `recipients[i].classical_epk`; X-Wing names this `ct_X` because in
  X-Wing's KEM model it plays the role of an ephemeral KEM ciphertext).
- `pk_X` is the recipient's 32-byte X25519 long-term public key (from
  the recipient's canonical public key).

KEK length is 32 bytes.

**Rationale.** This is the construction defined and analyzed in
draft-connolly-cfrg-xwing-kem and proven IND-CCA in the ROM and QROM by
Barbosa et al. (2024). Critically for hybrid-confidentiality: the SHA-3
input binds both `ct_X` and `pk_X`, so the KEK is cryptographically tied
to the specific ciphertext and the specific recipient public key. PQF
0.3.x used an in-house HKDF-concatenate-then-extract combiner that
omitted this binding; that construction is removed.

**Per-file and per-recipient binding.** X-Wing's combiner has no salt
slot for the file instance or the recipient slot. PQF binds those at the
DEK-wrap AEAD layer instead:

```
wrapped_dek_aad = file_id (16 bytes) || recipient_index (uint32 BE)
```

A KEK derived for recipient `i` cannot unwrap the DEK wrap of recipient
`j` (AADs differ), and a KEK from one file cannot unwrap any other
file's wrap (`file_id` differs). The cross-recipient and cross-file
isolation properties asserted in §8.5 and §8.7 are therefore preserved.

The per-chunk HKDF expansion that derives `chunk_key` from the DEK
(§5.2) is unchanged.

### 2.5 Header encoding

The header is encoded as **deterministic CBOR** per RFC 8949 §4.2.2.

Deterministic CBOR encoding rules (informative summary; RFC 8949 §4.2.2 is
normative):

1. Integers use the shortest form
2. Definite-length encoding for all items (no indefinite-length)
3. Map keys sorted by byte-wise lexicographic order of their encoded form (length first, then lexicographic)
4. No duplicate map keys
5. Floating-point numbers MUST NOT appear
6. Text strings (`tstr`) use UTF-8
7. Byte strings (`bstr`) are native — no base64 wrapping

**Rationale.** Deterministic CBOR eliminates the canonicalization ambiguity
that has historically affected signed-JSON formats. A given data structure
has exactly one valid deterministic CBOR encoding, so signature verification
does not require byte-level serialization comparison logic.

**Determinism enforcement (normative).** A conforming reader MUST verify that
the header CBOR encoding is deterministic per RFC 8949 §4.2.2. This MUST be
implemented by one of:

1. A CBOR parser that enforces deterministic encoding during parsing and
   rejects any input that does not conform, OR
2. A CBOR parser whose output is then re-encoded using deterministic rules,
   with byte-for-byte equality verified against the original input.

Permissive CBOR parsing — accepting non-deterministic encoding and silently
normalizing — is non-conforming. Most off-the-shelf CBOR libraries default to
permissive parsing; implementers MUST verify the library in use either
enforces determinism natively or implement option 2 above as a post-parse
validation step.

---

## 3. File layout

A PQF v1 file is a sequence of sections in order, with no padding or gaps:

```
+---------------------------------------------------+  offset 0
|  Magic: "PQF1" (4 bytes, ASCII)                   |
+---------------------------------------------------+  offset 4
|  Version: uint16 BE (0x0001)                      |
+---------------------------------------------------+  offset 6
|  Header length: uint32 BE (N bytes)               |
+---------------------------------------------------+  offset 10
|  Header: deterministic CBOR, N bytes              |
+---------------------------------------------------+  offset 10 + N
|  Header signature: 4691 bytes                     |  (present iff header.signer != null)
+---------------------------------------------------+  offset 10 + N (+ 4691 if signed)
|  Payload chunks (see §5)                          |
+---------------------------------------------------+
|  Footer: 20 bytes (see §5.5)                      |
+---------------------------------------------------+
|  File signature: 4691 bytes                       |  (present iff header.signer != null)
+---------------------------------------------------+  EOF
```

**Offset note.** When `header.signer` is null or absent, the header signature
and file signature fields are omitted entirely. Absence is absence — there
are no placeholder zero-length fields. The reader determines presence from
the value of `header.signer`.

**Header length prefix.** Retained despite CBOR being self-delimiting. The
prefix enables bounded parsing (reader checks length is sane before invoking
the CBOR parser) and is a defensive layer against CBOR parser bugs. Maximum
header length is 1,048,576 bytes (1 MiB); readers MUST reject larger values.
This limit prevents resource-exhaustion attacks via oversized headers while
comfortably exceeding expected v1 header sizes — a signed file with 100
recipients requires approximately 180 KiB of header, well within the limit.

---

## 4. Header format

### 4.1 Header schema

The header is a CBOR map with the following fields. CBOR diagnostic notation
is used below for illustration only; the on-disk encoding is deterministic
CBOR binary. A machine-checkable CDDL counterpart lives at
[`spec/pqf-header.cddl`](./pqf-header.cddl) and is enforced in CI.

```
{
  "alg": {
    "aead":     "aes-256-gcm-chunked",
    "combiner": "x-wing",
    "kdf":      "hkdf-sha256",
    "kem":      "x25519+ml-kem-768",
    "sig":      "ed25519+ml-dsa-87"
  },
  "chunk_size": 65536,
  "created":    0(2026-04-21T14:30:00Z),   / CBOR tag 0: RFC 3339 datetime /
  "file_id":    h'...' (16 bytes),
  "recipients": [
    {
      "classical_epk":     h'...' (32 bytes),
      "pqc_ct":            h'...' (1088 bytes),
      "wrapped_dek":       h'...' (48 bytes),
      "wrapped_dek_nonce": h'...' (12 bytes)
    }
  ],
  "signer": {
    "classical_pub": h'...' (32 bytes),
    "pqc_pub":       h'...' (2592 bytes)
  }
}
```

### 4.2 Field definitions

| Field | CBOR type | Required | Description |
|---|---|---|---|
| `alg` | map | Yes | Algorithm identifiers; see §4.2.1 |
| `chunk_size` | uint | Yes | Power of 2 between 4096 and 16777216 |
| `created` | tag 0 (text) | Yes | RFC 3339 datetime in UTC ("Z" suffix) |
| `file_id` | bstr (16) | Yes | 16 random bytes; used as AAD throughout file |
| `recipients` | array | Yes | Non-empty; see §4.2.2 |
| `signer` | map | No | If absent or CBOR null, file is unsigned; see §4.2.3 |

#### 4.2.1 `alg` map

All five fields are REQUIRED. Exact string values are REQUIRED. No other
fields are permitted inside `alg`.

| Field | Required value |
|---|---|
| `aead` | `"aes-256-gcm-chunked"` |
| `combiner` | `"x-wing"` |
| `kdf` | `"hkdf-sha256"` |
| `kem` | `"x25519+ml-kem-768"` |
| `sig` | `"ed25519+ml-dsa-87"` |

#### 4.2.2 `recipients` array

Each recipient is a CBOR map containing exactly four fields:

| Field | CBOR type | Size | Meaning |
|---|---|---|---|
| `classical_epk` | bstr | 32 bytes | Sender's ephemeral X25519 public key for this recipient (X-Wing `ct_X`) |
| `pqc_ct` | bstr | 1088 bytes | ML-KEM-768 ciphertext (X-Wing `ct_M`) |
| `wrapped_dek` | bstr | 48 bytes | 32-byte DEK ciphertext + 16-byte GCM tag |
| `wrapped_dek_nonce` | bstr | 12 bytes | Nonce for DEK-wrapping AES-GCM |

Readers MUST validate exact byte-string lengths and refuse on mismatch. No
other fields are permitted inside a recipient map.

#### 4.2.3 `signer` map

Present iff the file is signed. Contains exactly two fields:

| Field | CBOR type | Size |
|---|---|---|
| `classical_pub` | bstr | 32 bytes (Ed25519 public key) |
| `pqc_pub` | bstr | 2592 bytes (ML-DSA-87 public key) |

No other fields are permitted inside `signer`.

### 4.3 Extensibility policy

**Version 1 rejects all unknown fields.** This applies at every nesting
level: the top-level header map, `alg`, `recipients[*]`, and `signer`.

Readers MUST refuse a file containing any field name not listed above.

Extensions and new algorithms require a format version bump (§10).

---

## 5. Payload encoding

### 5.1 Chunking

The plaintext is divided into chunks of `header.chunk_size` bytes. The final
chunk MAY be smaller than `chunk_size` but MUST be at least 1 byte. An empty
file is encoded as zero chunks.

### 5.2 Per-chunk encryption

For chunk index `i` (0-based, uint64):

```
chunk_key   = HKDF-Expand(dek, info = "PQF1-chunk-v1" || i (8 bytes BE), L = 32)
chunk_nonce = 12 bytes, all zero
aad         = file_id (16 bytes) || i (8 bytes BE) || is_final (1 byte: 0x00 or 0x01)
ciphertext  = AES-256-GCM-Encrypt(chunk_key, chunk_nonce, plaintext_chunk, aad)
```

The `is_final` flag is `0x01` for the last chunk and `0x00` otherwise. This
binds the final-chunk position into the authentication tag and prevents
truncation attacks.

**Rationale for per-chunk HKDF + zero nonce.** Because each chunk has a
unique, never-reused key, a fixed zero nonce satisfies NIST SP 800-38D's
AES-GCM safety envelope by construction.

### 5.3 On-disk chunk format

```
+-----------------------------+
| Chunk length: uint32 BE     |  length of ciphertext + tag
+-----------------------------+
| Chunk flags: uint8          |  bit 0 = is_final, bits 1-7 = reserved MUST be 0
+-----------------------------+
| Ciphertext + 16-byte tag    |
+-----------------------------+
```

Chunks are written consecutively. The footer (§5.5) follows the final chunk
immediately.

Reserved flag bits MUST be zero on write, and any non-zero reserved bit
MUST cause refusal on read.

**Bounded chunk length.** Readers MUST verify that the declared chunk length
does not exceed the remaining bytes in the file (accounting for the known
trailing structure: 20-byte footer + optional 4691-byte file signature).
A chunk length that would read past the file bounds MUST cause refusal.
This prevents reader allocation attacks via crafted oversized length
fields.

### 5.4 Maximum file size

With uint64 chunk index and 16 MiB max chunk size, maximum theoretical
plaintext is ~2^88 bytes. No practical limit.

### 5.5 Footer

The footer is a 20-byte structure immediately following the final chunk:

```
+-------------------------------------+
| Footer magic: "PQFE" (4 bytes)      |
+-------------------------------------+
| Total chunk count: uint64 BE        |
+-------------------------------------+
| Total plaintext bytes: uint64 BE    |
+-------------------------------------+
```

**Footer validation.** Readers MUST compare both footer values against the
values observed during payload processing:

- `total_chunk_count` MUST equal the number of chunks read
- `total_plaintext_bytes` MUST equal the sum of decrypted plaintext lengths

Any mismatch is a fatal error. This validation is REQUIRED and is separate
from AEAD tag verification and file signature verification.

The footer is covered by the file signature (§6.2 step 9) when the file is
signed.

---

## 6. Cryptographic operations

### 6.1 Keygen

A PQF decryption identity consists of:

```
identity = (x25519_sk, x25519_pk, mlkem_sk, mlkem_pk)
public   = (x25519_pk, mlkem_pk)
```

A PQF signing identity consists of:

```
signing_identity = (ed25519_sk, ed25519_pk, mldsa_sk, mldsa_pk)
signing_public   = (ed25519_pk, mldsa_pk)
```

Implementations MUST generate all private keys using a cryptographically
secure random source.

### 6.2 Encryption

Given plaintext stream `P`, recipient public keys `[R_0, R_1, ...]`, and
optionally a signing identity `S`:

1. Generate a random 32-byte DEK.
2. Generate a random 16-byte `file_id`.
3. For each recipient `R_i` (i = 0, 1, ...):
   a. Generate ephemeral X25519 keypair `(esk_i, epk_i)`.
   b. `ss_classical = X25519(esk_i, R_i.x25519_pk)`.
   c. `(ss_pqc, ct_pqc) = MLKEM.Encap(R_i.mlkem_pk)`.
   d. Derive KEK per §2.4 using actual `file_id` and `recipient_index = i`.
   e. Generate random 12-byte `wrap_nonce_i`.
   f. `wrapped_dek_i = AES-256-GCM-Encrypt(KEK, wrap_nonce_i, DEK, aad = file_id)`.
   g. Append recipient block to header.
4. Encode the header as deterministic CBOR per §2.5.
5. If `S` is provided:
   a. `ed25519_header_sig = Ed25519.Sign(S.ed25519_sk, header_bytes)`.
   b. `mldsa_header_sig = ML-DSA-87.Sign(S.mldsa_sk, header_bytes)`.
   c. `header_signature = ed25519_header_sig || mldsa_header_sig` (4691 bytes).
6. Write file prefix: magic + version + header_length + header + (header_signature if signed).
7. Stream payload as chunks per §5. Compute a running SHA-256 over all
   on-disk chunk bytes (length prefixes + flags + ciphertexts + tags, in
   the order written). Track `chunk_count` and `total_plaintext_bytes`.
8. Write footer: `"PQFE" || chunk_count (uint64 BE) || total_plaintext_bytes (uint64 BE)`.
9. If `S` is provided: compute and write `file_signature` (4691 bytes) as
   hybrid signature over:
   ```
   file_id (16) || sha256_of_chunks (32) || footer (20 bytes)
   ```

### 6.3 Decryption (common steps)

Both processing modes (§6.4) share these initial steps:

1. Read and validate magic (`"PQF1"`) and version (`0x0001`).
2. Read header_length. Refuse if > 1 MiB.
3. Read header bytes.
4. Parse as deterministic CBOR per §2.5. Refuse on any of:
   - Non-deterministic encoding (keys out of order, indefinite-length items, etc.)
   - Duplicate keys
   - Unknown fields at any level (§4.3)
   - Missing required fields
   - Field values outside declared ranges or sizes
5. Validate `alg` fields exactly match v1 values (§4.2.1).
6. Validate `chunk_size` is a power of 2 in range [4096, 16777216].
7. If `signer` is present:
   a. Read 4691 bytes as `header_signature`.
   b. Split: `ed25519_sig = header_signature[0..64]`, `mldsa_sig = header_signature[64..4691]`.
   c. Verify `Ed25519.Verify(signer.classical_pub, header_bytes, ed25519_sig)`.
   d. Verify `ML-DSA-87.Verify(signer.pqc_pub, header_bytes, mldsa_sig)`.
   e. If EITHER verification fails, refuse.
8. For each recipient block in order, attempt to recover the DEK with the
   reader's identity `I`:
   a. `ss_classical = X25519(I.x25519_sk, epk_i)`.
   b. `ss_pqc = MLKEM.Decap(I.mlkem_sk, ct_pqc)`. ML-KEM decap does NOT fail
      on malformed ciphertext — it returns a pseudorandom secret (implicit
      rejection). Implementations MUST NOT short-circuit on any perceived
      failure in this step.
   c. Derive KEK per §2.4 using `recipient_index = i`.
   d. Attempt `DEK = AES-256-GCM-Decrypt(KEK, wrap_nonce_i, wrapped_dek_i, aad = file_id)`.
   e. If the GCM tag verifies, retain the DEK and continue processing
      remaining recipient blocks for constant-time hygiene (§6.5).
   f. If no recipient block succeeded after trying all of them, refuse:
      "not a recipient."

### 6.4 Processing modes (normative)

PQF defines two processing modes. Implementations MUST support
**Authenticated Mode**. Implementations MAY support **Streaming Mode**. An
application requesting a mode the implementation does not support MUST
receive an error, not a silent fallback.

#### 6.4.1 Authenticated Mode

In Authenticated Mode, plaintext MUST NOT be released to the caller until
the file signature has been verified (for signed files) or the footer has
been validated (for unsigned files).

Procedure:

1. Perform §6.3 common steps.
2. Buffer (or perform a two-pass read over) the payload.
3. Decrypt each chunk per §5.2. Track running SHA-256 over on-disk chunk
   bytes, chunk count, and plaintext byte count.
4. Read the 20-byte footer. Validate `total_chunk_count` and
   `total_plaintext_bytes` match observed values. If either mismatches,
   refuse. Retain the exact 20 footer bytes as read from the file.
5. If signed: read 4691-byte file_signature, split as in §6.3 step 7b,
   verify both halves over `file_id || sha256_of_chunks || footer_bytes`,
   where `footer_bytes` is the exact 20 bytes retained in step 4. The bytes
   used in signature verification MUST be byte-identical to the bytes read
   from the file; re-encoding the parsed footer values is non-conforming.
   If EITHER signature half fails, refuse.
6. Release plaintext to the caller.

This mode is appropriate for applications that rely on sender authenticity
and must not act on unauthenticated data.

#### 6.4.2 Streaming Mode

In Streaming Mode, plaintext MAY be released to the caller as each chunk's
AEAD tag verifies, before the file signature (if any) is verified.

Applications using Streaming Mode MUST treat released plaintext as
unauthenticated with respect to sender identity until the final verification
step completes successfully.

Procedure:

1. Perform §6.3 common steps.
2. For each chunk: decrypt per §5.2. On AEAD tag success, release the chunk's
   plaintext to the caller. Update running SHA-256, chunk count, plaintext
   byte count.
3. Read the 20-byte footer. Validate counts as in §6.4.1 step 4. On mismatch,
   signal the caller that data emitted so far is invalid and refuse.
4. If signed: verify file_signature as in §6.4.1 step 5. On failure, signal
   the caller that previously emitted data failed authentication.

**Failure signaling (normative).** Implementations supporting Streaming Mode
MUST provide a mechanism by which the caller can reliably detect post-hoc
authentication failure (footer mismatch or file signature failure after
plaintext has been emitted). The mechanism MUST be impossible for the caller
to overlook through ordinary use — for example, a thrown exception that
propagates, a non-zero return code that must be checked, or an explicit
`Result` type. Silent failure, log-only reporting, or mechanisms that require
the caller to opt in to noticing failure are non-conforming.

This mode is appropriate for very large files where buffering is impractical,
but places responsibility on the calling application to handle post-hoc
verification failure.

### 6.5 Constant-time recipient trial

Implementations MUST attempt all recipient blocks even after one succeeds,
to avoid leaking the recipient index through timing. Secrets from non-matching
attempts are discarded and zeroed.

**Recipient count guidance.** Implementations SHOULD support at least 100
recipients per file. Cost scales linearly: each trial requires one X25519
scalar multiplication, one ML-KEM-1024 decapsulation, one HKDF derivation,
and one AES-GCM decrypt attempt.

### 6.6 Secret hygiene

Implementations MUST zero all intermediate secrets (shared secrets, DEKs,
chunk keys, KEKs) after use. Private keys SHOULD be zeroed when their
identity object is disposed.

---

## 7. Public key / identity formats

PQF public keys have three representations. Each has a specific purpose.

### 7.1 Canonical binary format (primary)

The canonical binary encoding of a PQF hybrid encryption public key is:

```
+-----------------------------------+
| Version: uint8 (0x01)             |
+-----------------------------------+
| X25519 public key: 32 bytes       |
+-----------------------------------+
| ML-KEM-768 public key: 1184 bytes |
+-----------------------------------+
```

Total: **1217 bytes**.

The canonical binary encoding of a PQF hybrid signing public key is:

```
+-----------------------------------+
| Version: uint8 (0x01)             |
+-----------------------------------+
| Ed25519 public key: 32 bytes      |
+-----------------------------------+
| ML-DSA-87 public key: 2592 bytes  |
+-----------------------------------+
```

Total: **2625 bytes**.

The canonical binary format is used in files, APIs, and all programmatic
processing. It is the input to signature generation and fingerprint
computation.

### 7.2 PEM-armored format (transport)

For human-exchangeable transport (email, documentation, cross-system paste),
PQF public keys are encoded in PEM format per RFC 7468:

```
-----BEGIN PQF PUBLIC KEY-----
<standard base64 of canonical binary, line-wrapped at 64 characters>
-----END PQF PUBLIC KEY-----
```

```
-----BEGIN PQF SIGNING PUBLIC KEY-----
<standard base64 of canonical binary, line-wrapped at 64 characters>
-----END PQF SIGNING PUBLIC KEY-----
```

PEM uses standard base64 (RFC 4648 §4) with `=` padding, line-wrapped at 64
characters. Writers MUST emit exact label strings above. Readers MUST accept
any line endings (LF or CRLF) and any ASCII whitespace between header,
base64 body, and footer.

### 7.3 Fingerprint format (verification)

A PQF fingerprint is SHA-256 over the canonical binary encoding of a public
key:

```
fingerprint = SHA-256(canonical_binary_public_key)
```

Total: **32 bytes** of hash output.

**Display formats:**

- **Full hex:** 64 lowercase hexadecimal characters
  - Example: `9f3c7a2e4b1d6f8c3e5a8b2d4f6c9e1a3b5d7f8c2e4a6b9d1f3c5e7a9b1d3f5c`
- **Short form:** First 8 bytes (16 hex characters) for space-constrained UI
  - Example: `9f3c7a2e4b1d6f8c`
- **Prefixed form** (for context in displays): `pqf1fp:<hex>`

Implementations MAY offer additional display encodings (base32, base58, etc.)
provided the underlying 32-byte hash is the same.

**CRITICAL RULE.** Fingerprints are for human verification only. Fingerprints
MUST NOT be used as identifiers for cryptographic operations, as database
primary keys for public keys, as lookup keys in key stores, or in any
automated identity-matching logic. The canonical binary form is the sole
cryptographic identifier.

### 7.4 Private key format

Private keys are out of scope for v1. Implementations MAY use any format
provided public-key export follows §7.1 and §7.2. A canonical private-key
format will be defined in v2.

---

## 8. Security considerations

### 8.1 Hybrid security assumption

Confidentiality holds if AT LEAST ONE of:

- The ECDLP on Curve25519 remains hard (classical)
- ML-KEM-768 remains IND-CCA2 secure (post-quantum)

Sender authenticity (for signed files) holds if AT LEAST ONE of:

- Ed25519 remains unforgeable
- ML-DSA-87 remains unforgeable

A complete break of BOTH halves of a hybrid construction is required to
violate the corresponding property.

### 8.2 What PQF does NOT defend against

- **Traffic analysis.** File size leaks plaintext size up to chunk granularity.
- **Metadata disclosure.** `created`, `file_id`, `chunk_size`, and recipient
  count are unencrypted.
- **Recipient anonymity against metadata analysis.** The format hides
  recipient public keys, but does not provide recipient anonymity against
  traffic analysis or cross-file correlation. Implementations that preserve
  recipient ordering across files may enable linkage. The number and relative
  order of recipient blocks are visible.
- **Sender authenticity on unsigned files.** Any recipient who can decrypt
  could also have fabricated the file.
- **Side channels in primitive implementations.** PQF relies on ML-KEM and
  ML-DSA implementations being constant-time. The spec cannot enforce this.
- **Compromised random number generator.** If DEK, `file_id`, or ephemeral
  keys are predictable, confidentiality is lost.
- **Endpoint compromise.** An attacker with access to a recipient's identity
  can decrypt any file encrypted to that identity.
- **Malicious signer.** A valid signature proves the signer's private keys
  produced it. It does not prove content truth.

### 8.3 Signature coverage

When signed, PQF binds the following:

- **Header signature** covers: algorithm identifiers, `chunk_size`, `created`,
  `file_id`, recipient list, signer public keys.
- **File signature** covers: `file_id || sha256(chunk_bytes) || footer`.
  Where `footer` is the full 20 bytes including the footer magic, chunk
  count, and plaintext byte count.

Together these prevent: header tampering, recipient substitution, chunk
reordering, chunk insertion/deletion, truncation, and footer tampering.

### 8.4 Fail-closed requirements

Implementations MUST refuse a file under any of these conditions:

- Magic or version mismatch
- Header length > 1 MiB
- Non-deterministic CBOR encoding (ordering, indefinite-length, duplicate keys)
- Unknown field at any level of the header
- Missing required field
- Algorithm identifier mismatch
- `chunk_size` invalid
- `created` not in RFC 3339 UTC form with `Z` suffix
- Empty `recipients` array
- Binary field length mismatch
- Identity matches no recipient block
- Any signature verification failure (either hybrid half)
- Any AEAD tag failure
- Footer chunk count or plaintext byte count mismatch
- Footer magic missing or incorrect
- Reserved chunk flag bits set
- Chunk length exceeds remaining file bounds
- Truncation (EOF before expected end)
- Trailing data after expected EOF

"Partial success" on any of these conditions is non-conforming.

### 8.5 Replay and substitution

`file_id` is included as AAD in every AEAD operation: in the chunk AEAD
(§5.2) and in the DEK-wrap AEAD (§2.4). This binds the DEK wrap and all
chunks to the specific file instance. An attacker cannot splice chunks
between files or replace recipient blocks across files. (In PQF 0.3.x
this binding was layered: `file_id` was both in the HKDF-Extract salt
and in the AEAD AAD. Under X-Wing the HKDF salt is gone, but the AEAD
binding alone is sufficient for cross-file isolation.)

### 8.6 Downgrade resistance

The `alg` field is covered by the header signature when present, and is
always verified against exact-match string values. Unknown algorithm
identifiers cause refusal (§4.3). Downgrade to weaker primitives within v1 is
not possible.

### 8.7 Multi-target and cross-recipient isolation

X-Wing's combiner binds the recipient's X25519 public key (`pk_X`) into
the KDF input (§2.4), so each recipient's KEK is intrinsically tied to
their own long-term key. In addition, the DEK-wrap AEAD's AAD includes
`recipient_index` alongside `file_id`, so even if two recipient slots
somehow derived the same KEK (they cannot under X-Wing because their
`pk_X` differs), the wrapped-DEK tags would still mismatch on the wrong
slot.

Compromise of one recipient's identity does not reveal any other
recipient's KEK or DEK.

### 8.8 Deniability semantics

ML-KEM uses implicit rejection: on malformed ciphertext, decap returns a
pseudorandom secret rather than signaling failure. Combined with PQF's
recipient-trial decryption (§6.3 step 8), this has the following property:

From the perspective of an observer who does not hold any recipient's private
keys, a recipient's attempt to decrypt a PQF file is cryptographically
indistinguishable from an attempt by a non-recipient. Both produce "AEAD tag
failure" on non-matching blocks.

This provides **weak deniability**: a party cannot prove to a third party
that they were NOT a recipient simply by demonstrating failed decryption,
since the same failure occurs whether or not they are a recipient.

This property is a consequence of ML-KEM's CCA-security design and PQF's
constant-time trial. It is not a strong cryptographic deniability guarantee
of the kind offered by protocols explicitly designed for deniability (e.g.,
OTR, Signal's deniability properties). It is noted here because:

- Applications may rely on it and should know the limits
- Applications may misunderstand it and should be corrected
- Specification completeness requires naming it

PQF is not a deniability protocol. Any stronger deniability claim is out of
scope for v1.

---

## 9. Conformance

This section defines conformance classes for implementations.

### 9.1 Conforming writer

A conforming writer:

- MUST produce files matching the byte layout of §3
- MUST encode the header as deterministic CBOR per §2.5
- MUST populate all required header fields with valid values
- MUST use the v1 algorithms exactly as specified in §2
- MUST use cryptographically secure randomness for DEK, `file_id`, ephemeral keys, and wrap nonces
- MUST compute and write the footer with accurate `total_chunk_count` and `total_plaintext_bytes`
- MUST write signatures per §6.2 step 9 when a signing identity is provided, covering file_id + chunk hash + footer
- MUST zero intermediate secrets per §6.6

### 9.2 Conforming reader (Authenticated Mode)

A conforming reader supporting Authenticated Mode:

- MUST implement all refusal conditions in §8.4
- MUST verify the file signature (when present) before releasing plaintext
- MUST validate the footer before releasing plaintext
- MUST attempt all recipient blocks for constant-time trial (§6.5)
- MUST NOT short-circuit on ML-KEM decap "failure" (§6.3 step 8b)
- MUST reject unknown header fields at every level

### 9.3 Conforming reader (Streaming Mode)

A conforming reader supporting Streaming Mode:

- MUST meet all requirements of §9.2 except the pre-release buffering
- MUST signal post-hoc failure to the caller if footer validation or file signature verification fails after plaintext has been released
- MUST NOT silently discard post-hoc verification failures

Implementations MAY support Authenticated Mode only; they are not required to
offer Streaming Mode.

### 9.4 Conforming verifier

A conforming signature verifier:

- MUST verify both classical and post-quantum signature halves
- MUST refuse if either half fails, regardless of the other
- MUST NOT accept truncated or extended signatures (fixed 4691-byte length)

### 9.5 Conforming key format implementation

A conforming key format implementation:

- MUST implement the canonical binary format (§7.1) for all programmatic use
- SHOULD implement the PEM-armored format (§7.2) for transport
- MAY implement fingerprints (§7.3) for user-facing verification
- MUST NOT use fingerprints as cryptographic identifiers (§7.3)

---

## 10. Versioning and evolution

### 10.1 What requires a format version bump

A new file format version (v2, v3, ...) is required for any change that
causes a v1 file to validate differently, or that a v1-only reader could not
process correctly. This includes:

- Any change to the byte layout of §3
- Any change to required or optional header fields
- Any change to algorithm identifiers or required primitive set
- Any change to the combiner construction
- Any change to chunk or footer encoding
- Any change to signature coverage

New versions are NOT required to be backward-compatible with v1 files.

### 10.2 What requires a profile identifier

A "profile" mechanism is not defined in v1. If future versions introduce
profiles (e.g., to support multiple primitive suites within a single major
version), the mechanism will be defined explicitly in that version.

### 10.3 What does NOT require a version bump

The following are spec-document changes that do NOT affect file format:

- Editorial clarifications to non-normative prose
- Additions to informative examples
- Corrections to cross-references
- New test vectors (as long as existing vectors remain valid)
- Additions to Appendix A (implementation notes)

Such changes MAY increment the document version (0.x.y) without changing
the file format version.

### 10.4 Frozen elements of v1

Once v1 reaches 1.0.0 (non-experimental):

- The byte layout of §3 is frozen
- The primitive set of §2 is frozen
- The header field set of §4 is frozen
- The combiner construction of §2.4 is frozen
- The footer structure of §5.5 is frozen

A file that validates under v1 1.0.0 MUST continue to validate under all
future versions of the v1 reference implementation.

---

## 11. Threat model

### 11.1 Properties PQF provides

| Property | How |
|---|---|
| Confidentiality at rest (hybrid PQ) | §2.1 X-Wing (X25519+ML-KEM-768), §2.3 AEAD, §2.4 combiner |
| Payload integrity | Per-chunk AEAD tags, footer validation |
| Sender authenticity (optional) | §2.2 hybrid signatures |
| Replay resistance across files | `file_id` in AAD and salt (§8.5) |
| Cross-recipient isolation | `recipient_index` in salt (§8.7) |
| Downgrade resistance | Exact-match `alg` validation (§8.6) |
| Truncation resistance | `is_final` in AAD + footer counts + file signature |
| Weak recipient deniability | ML-KEM implicit rejection + constant-time trial (§8.8) |

### 11.2 Properties PQF does NOT provide

| Property | Why out of scope |
|---|---|
| Traffic analysis resistance | File size visible |
| Metadata confidentiality | Header fields in cleartext |
| Recipient anonymity | Recipient count visible; correlation possible |
| Forward secrecy (messaging sense) | Files are static artifacts |
| Endpoint compromise protection | Keys held locally are exposed on compromise |
| Strong deniability | See §8.8 |
| Post-compromise security | No rekeying mechanism |
| Authenticity on unsigned files | Signer is optional |

### 11.3 Assumed adversary capabilities

PQF is designed against adversaries with:

- Full access to ciphertext files
- Unlimited classical computation
- Future access to a cryptographically relevant quantum computer
- Ability to modify files in transit or storage
- Ability to choose plaintexts for encryption (chosen-plaintext)
- Ability to submit ciphertexts to recipients (chosen-ciphertext — within CCA bounds of underlying primitives)

PQF does NOT assume the adversary has:

- Read access to the recipient's private keys
- Control over the random number generator used during encryption
- Ability to observe timing of primitive implementations (primitives MUST be constant-time; PQF cannot enforce)

---

## 12. Interoperability

### 12.1 Test vectors

Conformance requires passing all test vectors published at:

```
https://github.com/systemslibrarian/PostQuantum.FileFormat/tree/main/test-vectors/v1/
```

Required positive test vectors:

- TV-001: Single recipient, unsigned, 1 KiB plaintext
- TV-002: Single recipient, signed, 1 KiB plaintext
- TV-003: Three recipients, signed, 100 KiB plaintext, multi-chunk
- TV-004: Empty plaintext (zero chunks)
- TV-005: Single chunk at exact `chunk_size` boundary
- TV-006: Plaintext = `chunk_size + 1` byte (forces 1-byte final chunk)
- TV-007: Maximum `chunk_size` (16 MiB)
- TV-008: Minimum `chunk_size` (4 KiB)
- TV-009: 100 recipients, unsigned, 10 KiB plaintext
- TV-010: Signed file processed in Authenticated Mode
- TV-011: Signed file processed in Streaming Mode
- TV-012: Key format — canonical binary round-trip
- TV-013: Key format — PEM round-trip
- TV-014: Key format — fingerprint computation

Required negative test vectors:

- TV-NEG-001: Malformed magic — refuse
- TV-NEG-002: Wrong version — refuse
- TV-NEG-003: Truncated final chunk — refuse
- TV-NEG-004: Modified `alg.kem` — refuse
- TV-NEG-005: Modified chunk ciphertext — refuse
- TV-NEG-006: Modified header on signed file — refuse
- TV-NEG-007: Extra recipient on signed file — refuse
- TV-NEG-008: Swapped chunks — refuse
- TV-NEG-009: Non-deterministic CBOR (bad ordering) — refuse
- TV-NEG-010: Duplicate CBOR key — refuse
- TV-NEG-011: Unknown top-level header field — refuse
- TV-NEG-012: Unknown field inside `alg` — refuse
- TV-NEG-013: Wrong binary length (`wrapped_dek`) — refuse
- TV-NEG-014: Reserved chunk flag bit set — refuse
- TV-NEG-015: Footer chunk count mismatch — refuse
- TV-NEG-016: Footer plaintext bytes mismatch — refuse
- TV-NEG-017: Modified footer on signed file — refuse
- TV-NEG-018: Header length > 1 MiB — refuse
- TV-NEG-019: Non-deterministic CBOR (valid parse, non-deterministic encoding) — refuse
- TV-NEG-020: Chunk length exceeds remaining file bounds — refuse
- TV-NEG-021: `created` not in RFC 3339 UTC "Z" form — refuse
- TV-NEG-022: Streaming Mode signed file with post-hoc signature failure — caller MUST receive authentication failure signal

### 12.2 Test vector file format

Each test vector is a directory containing a `manifest.json` and fixture files:

```json
{
  "id": "TV-003",
  "description": "Three recipients, signed, 100 KiB plaintext",
  "spec_version": "1",
  "kind": "positive",
  "processing_mode": "authenticated",
  "inputs": {
    "recipient_identities": ["identity-alice.bin", "identity-bob.bin", "identity-carol.bin"],
    "signer_identity": "signer.bin",
    "plaintext": "plaintext.bin",
    "randomness": "randomness.bin"
  },
  "expected": {
    "file": "expected.pqf",
    "decrypted_plaintext_sha256": "<hex>"
  }
}
```

The `processing_mode` field MAY be `"authenticated"`, `"streaming"`, or
`"either"`.

Binary fixture format for decryption identities:
`version (0x01) || x25519_sk (32) || x25519_pk (32) || mlkem_sk (2400) || mlkem_pk (1184)`

Binary fixture format for signing identities:
`version (0x01) || ed25519_sk (32) || ed25519_pk (32) || mldsa_sk (4896) || mldsa_pk (2592)`

### 12.3 Spec authority

When any implementation disagrees with this specification, **this
specification is authoritative**. Bug reports against implementations are
welcomed.

### 12.4 Stability

Once v1 reaches 1.0.0, §10.4 freeze applies. No changes will cause a v1 file
to fail validation under v1 rules.

---

## 13. Known gaps and limitations

- **No external cryptographic review.** As of this document date, the spec
  has not been reviewed by an independent cryptographer. The EXPERIMENTAL
  label applies until such review occurs.
- **ML-KEM and ML-DSA are young.** NIST standards finalized 2024. Cryptanalytic
  understanding continues to evolve. The hybrid construction mitigates but
  does not eliminate this risk.
- **No formal security proof of the overall assembly.** The KEM combiner
  is X-Wing, which has external IND-CCA proofs in ROM/QROM (Barbosa et
  al., 2024). The full PQF stack (X-Wing + per-recipient AEAD wrap +
  chunked AEAD + hybrid signatures + footer) is not formally modeled
  end-to-end.
- **Canonical CBOR dependency.** Deterministic CBOR is a tighter surface than
  canonical JSON, but cross-implementation interop still requires careful
  library selection. Implementations MUST test against published vectors.
- **No private key format.** Defined in v2.
- **No passphrase recipients.** Defined in v2 or later.
- **No hardware token support.** Standards for ML-KEM/ML-DSA on smartcards
  and HSMs not yet available.

---

## 14. References

### 14.1 Normative

- FIPS 203 — Module-Lattice-Based Key-Encapsulation Mechanism Standard (ML-KEM)
- FIPS 204 — Module-Lattice-Based Digital Signature Standard (ML-DSA)
- RFC 2119 — Requirement Levels
- RFC 4648 — Base Encodings
- RFC 5869 — HKDF
- RFC 7468 — Textual Encodings of PKIX (PEM format)
- RFC 7748 — X25519
- RFC 8032 — Ed25519
- RFC 8174 — Requirement Level Keywords (ambiguity)
- RFC 8949 — Concise Binary Object Representation (CBOR)
- NIST SP 800-38D — AES-GCM

### 14.2 Informative

- draft-connolly-cfrg-xwing-kem — X-Wing hybrid KEM
- Barbosa, Boyen, Connolly, Schwabe, Stehlé, Strub (2024) —
  "X-Wing: The Hybrid KEM You've Been Looking For"
- draft-ietf-pquip-hybrid-signature-spectrums
- age file format — https://age-encryption.org/v1
- RFC 8152 / 9052 — COSE (for signed-CBOR prior art)

---

## Appendix A — Reference implementation notes

*This appendix is NON-NORMATIVE. It describes properties of the reference
implementation published as the `PostQuantum.FileFormat` NuGet package. Other
implementations are not required to match these properties.*

### A.1 Platform requirements

The reference implementation targets .NET 8+. On .NET 10 with Windows
Server 2025 / Windows 11, or on Linux/macOS with OpenSSL 3.5+, ML-KEM and
ML-DSA are provided by `System.Security.Cryptography`. On older platforms,
BouncyCastle.Crypto is used as a fallback.

Test vectors MUST be produced and verified on both paths to catch interop
regressions between the native platform implementations and the BouncyCastle
fallback.

### A.2 API surface

The package exposes a public API with at minimum:

- `PqFile.EncryptAsync(input, output, recipients, signer?, mode?)`
- `PqFile.DecryptAsync(input, output, identity, mode)` where `mode ∈ {Authenticated, Streaming}`
- `PqIdentity.Generate()`, `PqIdentity.Import(...)`, `PqIdentity.Export(...)`
- `PqPublicKey.ToPem()`, `PqPublicKey.FromPem(...)`, `PqPublicKey.Fingerprint()`

The `verify_then_decrypt` semantic is the default (Authenticated Mode).
Streaming Mode is opt-in.

### A.3 CLI tool

A CLI tool named `pqf` is published as a .NET global tool. Subcommands:

- `pqf keygen` — generate an identity
- `pqf encrypt` — encrypt a file
- `pqf decrypt` — decrypt a file
- `pqf inspect` — display header and footer contents without decrypting
- `pqf fingerprint` — compute and display a public key fingerprint

### A.4 Deterministic randomness for test vectors

The reference implementation exposes a deterministic randomness source via
an internal API for test vector generation only. Production builds MUST NOT
expose this API.

---

## Document history

| Version | Date | Notes |
|---|---|---|
| 0.3.1 | 2026-04-21 | Polishing pass: CBOR determinism enforcement, header length justification, chunk length bounds, footer byte identity, Streaming Mode failure signaling, refusal-list additions |
| 0.3.0 | 2026-04-21 | ChatGPT review incorporated; CBOR encoding; dual key format; structured footer; conformance/versioning/threat sections; impl notes moved to appendix |
| 0.2.0 | 2026-04-21 | Grok review incorporated |
| 0.1.0 | 2026-04-21 | Initial DRAFT |
