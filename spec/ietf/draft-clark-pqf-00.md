---
title: "The PQF Post-Quantum File Format"
abbrev: PQF
docname: draft-clark-pqf-00
category: info
ipr: trust200902
submissiontype: independent
area: SEC
workgroup: Independent Submission
keyword:
  - post-quantum
  - hybrid encryption
  - file format
  - ML-KEM
  - ML-DSA

author:
  -
    fullname: Paul Clark
    organization: Independent
    email: systemslibrarian@gmail.com

normative:
  RFC2119:
  RFC8174:
  RFC8949:
  RFC7748:   # X25519
  RFC8032:   # Ed25519
  RFC5869:   # HKDF
  FIPS203:
    target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf
    title: "Module-Lattice-Based Key-Encapsulation Mechanism Standard"
    author:
      org: National Institute of Standards and Technology
    date: 2024
  FIPS204:
    target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf
    title: "Module-Lattice-Based Digital Signature Standard"
    author:
      org: National Institute of Standards and Technology
    date: 2024
  FIPS197:   # AES
  SP800-38D: # GCM

informative:
  PQF-SPEC:
    target: https://github.com/systemslibrarian/PostQuantum.FileFormat/blob/main/spec/PQF-SPEC-v1.md
    title: "PQF Wire Format Specification (draft v0.3.1)"
    author:
      ins: P. Clark
    date: 2026
  PQF-DESIGN:
    target: https://github.com/systemslibrarian/PostQuantum.FileFormat/blob/main/spec/PQF-DESIGN-RATIONALE-v1.md
    title: "PQF Design Rationale"
    author:
      ins: P. Clark
    date: 2026

--- abstract

This document describes PQF (Post-Quantum File Format), a binary container
format for encrypted files at rest that combines classical and post-quantum
cryptographic primitives in a hybrid construction. Confidentiality is
provided by an X25519/ML-KEM-1024 hybrid KEM; authenticity (when present)
is provided by an Ed25519/ML-DSA-87 hybrid signature. The format is
fail-closed by construction: any deviation from the wire format, including
unknown fields, non-deterministic encodings, reserved-bit usage, or
length-mismatches, terminates processing with an explicit error. This
document is an independent submission intended to solicit review of the
hybrid combiner construction, AEAD chunking, and signature coverage
definitions described in the companion reference specification.

--- middle

# Introduction

The migration to post-quantum cryptography is a multi-decade transition.
Files encrypted today must remain confidential against adversaries who
collect ciphertext now and decrypt later, once a cryptographically-relevant
quantum computer becomes available ("harvest now, decrypt later"). This
document specifies a file-at-rest container format whose default is
hybrid post-quantum confidentiality, not an optional extension.

PQF is explicitly NOT a transport protocol, a messaging protocol, or a
disk-encryption scheme. It is a single-file container.

## Goals

- Hybrid confidentiality holds if either the classical or the post-quantum
  primitive remains unbroken.
- Authenticity, when present, requires both halves to verify.
- The wire format is deterministically encodable; re-encoding a parsed
  header MUST produce identical bytes.
- All "MUST"s in the format definition correspond to refusal paths in any
  conforming reader. No permissive or best-effort recovery exists.

## Non-goals

- Anonymity or metadata privacy. The header is in plaintext and includes
  algorithm identifiers, recipient public-key material, signer public
  keys (when signed), the chunk size, and a timestamp.
- Network transport, key distribution, or trust establishment.
- Backward compatibility with OpenPGP packet structures or age.

## Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in
BCP 14 {{RFC2119}} {{RFC8174}} when, and only when, they appear in all
capitals, as shown here.

# Overview

A PQF file is a sequence of:

~~~
+-----------------------------------------+
| Magic "PQF1" (4 bytes)                  |
| Version u16 BE (currently 0x0001)       |
| Header length u32 BE                    |
| Header (deterministic CBOR per RFC 8949 |
|         section 4.2.2)                  |
| Header signature (4691 bytes, OPTIONAL) |
| Chunk stream:                           |
|   per chunk: 1B flags || 4B length BE   |
|              || ciphertext || 16B tag   |
| Footer (20 bytes)                       |
| File signature (4691 bytes, OPTIONAL)   |
+-----------------------------------------+
~~~

# Cryptographic primitives

## Hybrid KEM

The KEM combiner is `pqf1-bind-extract-v1`. For each recipient block,
the sender:

1. Performs an X25519 key agreement and an ML-KEM-1024 encapsulation,
   producing two shared secrets `ss_x` and `ss_kem`.
2. Computes a salt prefixed with the byte string `PQF1-combiner-v1`
   followed by the recipient-specific binding context (see {{PQF-SPEC}}
   for the exact layout).
3. Extracts a 32-byte key-encryption key (KEK) via HKDF-Extract
   {{RFC5869}} from `ss_x || ss_kem` using the prefixed salt.
4. AES-GCM-wraps the per-file data-encryption key (DEK) under the KEK.

Note that two distinct identifier strings are used: `pqf1-bind-extract-v1`
is the algorithm-identifier value carried in the CBOR header field
`alg.combiner`, while `PQF1-combiner-v1` is the literal byte prefix of
the HKDF salt. This is intentional and is one of the points on which
review is explicitly sought.

## Hybrid signatures

When signing is enabled, both Ed25519 {{RFC8032}} and ML-DSA-87 {{FIPS204}}
signatures are computed over the same coverage message and concatenated
into a fixed 4691-byte signature block. Either half failing to verify
refuses the file.

## Chunked AEAD

Plaintext is partitioned into chunks of the size declared in the header.
Each chunk is sealed with AES-256-GCM {{SP800-38D}} under a key derived
per-chunk via HKDF from the DEK, with the additional authenticated data
(AAD) bound to `file_id || chunk_index || is_final`. The nonce is the
fixed zero nonce; uniqueness is guaranteed by per-chunk key derivation.

# Wire format

See {{PQF-SPEC}} for the normative byte-level format. This document is
intended as a community-review surface for the construction; the
authoritative wire format remains the companion specification until
this document advances.

# Modes of decryption

A conforming reader MUST implement at least one of:

- **Authenticated Mode** (RECOMMENDED): verify the file signature
  (when present) and the footer before releasing any plaintext to the
  caller.
- **Streaming Mode**: release verified chunks as they are read, and
  surface post-hoc verification failures (file signature, footer
  reconciliation, trailing-data detection) explicitly. Streaming
  failures MUST NOT be silently ignored by the caller.

# Open review questions

The author specifically solicits review on:

1. Hybrid KEM combiner construction (HKDF salt/IKM layout, label binding).
2. Per-chunk AEAD construction and AAD binding.
3. File-signature coverage composition.
4. ML-KEM implicit-rejection timing and recipient-trial constant-time
   posture.
5. Whether the footer should be AEAD-bound on unsigned files.
6. Whether header-signature and file-signature messages should carry
   distinct domain-separation prefixes.

# Security considerations

PQF is fail-closed by design but security still depends on:

- Correct implementation of the underlying primitives (X25519, Ed25519,
  ML-KEM-1024, ML-DSA-87, AES-256-GCM, HKDF-SHA256).
- A correct implementation of this specification.
- A secure source of randomness on the encrypting host.

Side-channel posture is inherited from the underlying primitive
implementations. The reference implementation runs the recipient-trial
loop in constant time over recipient blocks but otherwise inherits
whatever properties the underlying primitive library provides.

Metadata is visible. The header is unencrypted.

# IANA considerations

This document has no IANA actions. Should it advance, the following
registrations would be required:

- A media type `application/pqf` (or similar) for the file format.
- Optional: a filename extension registration for `.pqf`.

--- back

# Acknowledgments

The author thanks the early reviewers of the reference specification
and the open-source post-quantum implementation community.
