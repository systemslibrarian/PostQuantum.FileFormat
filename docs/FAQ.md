# FAQ

Common questions about PQF, with links to deeper answers when they
exist. Open an issue if you have a question that should be here but
isn't.

## "Should I use PQF for my data today?"

**Probably not for irreplaceable data.** The spec is still draft
v0.3.1; the wire format is not frozen. The reference implementation
has not undergone external cryptographic review. See
[`docs/COMPATIBILITY.md`](./COMPATIBILITY.md) for the v1.0.0 freeze
contract and the blocker list. PQF is appropriate for:

- experimenting with hybrid post-quantum file formats,
- contributing to the spec or reference impl,
- exploring how PQ primitives compose,
- writing or running interop tests.

It is *not* yet appropriate for "I want to make sure my client's
legal archive is decryptable in twenty years."

## "Is PQF audited?"

Not yet. The README's "Cryptographic review wanted" section
enumerates the specific normative sections where review has the
highest leverage. If you do this kind of work, please open an issue.

## "Why hybrid? Just use ML-KEM."

Because ML-KEM is roughly two years old as a standard. The
cryptographic community has been wrong about lattice-based
primitives before (NTRUSign, the Newhope mistakes, the first version
of SIKE — actually broken). Hybrid means a defect in either ML-KEM
or X25519 alone does not compromise the file. We get post-quantum
resistance without giving up classical assurance. See
[`docs/DESIGN.md`](./DESIGN.md) for the longer argument.

## "Why CBOR, not Protocol Buffers / FlatBuffers / msgpack?"

Because CBOR has a deterministic-encoding profile in the standard
(RFC 8949 §4.2.2). Re-encoding a canonical CBOR value byte-for-byte
matches the input, which means tamper-detection on the header
becomes structural rather than hand-written. Protobuf and msgpack
don't have this property; FlatBuffers does at a different level of
the stack but doesn't have a deterministic-encoding policy in the
same way. See `docs/DESIGN.md`.

## "Why CBOR, not JSON?"

CBOR is a tighter wire encoding (binary), has a deterministic
profile, and supports raw byte strings without base64 overhead.
JSON would have worked but with more hand-written canonicalization
rules.

## "Can I use this in a browser?"

Yes, via the WebAssembly reader at
[`bindings/wasm`](../bindings/wasm). It's reader-only; producing
files in a browser is not yet wired up. The
[demo page](../bindings/wasm/demo/index.html) lets you drop a file
in and see the parsed header with zero network calls.

## "Is there a Python package?"

Yes, in [`bindings/python`](../bindings/python), reader-only via
pyo3. Not yet on PyPI; build from source with maturin for now.
PyPI publication is gated on v1.0.0 wire-format freeze.

## "Why .NET as the reference language?"

Historical: it's where the project started. The reference
implementation is the artifact that proves the spec is
implementable, and the goal of the spec-first approach is that a
second-source implementation in another language exists too. That
second source is the Rust reader, which catches divergence the
.NET impl alone can't.

If a second-source production writer in a language other than .NET
appeared, the project would be very happy to have it.

## "Why does the header have a `signer` field with the public key?"

So the verifier doesn't need an out-of-band key directory to verify
the file's signature. It also makes the signed-file contract very
explicit: the signer field is the public statement "this is the
key I am claiming signed this file." The verifier still has to
decide whether to trust that key — PQF does not solve key binding.

## "What stops someone from setting `signer = null` on a signed file?"

The hybrid signature also covers the header bytes. If you mutate
the header (including setting `signer` to null), the header
signature stops verifying. The threat-model writeup in
[`THREAT-MODEL.md`](./THREAT-MODEL.md) walks through this.

## "Why does Streaming Mode exist if Authenticated Mode is safer?"

Some files don't fit in memory, and some pipelines truly need
"verified bytes as they arrive." For those, Streaming Mode trades
the "verify-before-release" property for "verify-per-chunk +
verify-once-at-end." The catch is that the caller has to actually
check the end-of-stream result; the `[MustUseReturnValue]` on the
API surface catches casual misuse. See
[`STREAMING.md`](./STREAMING.md) for the decision matrix.

## "What's the minimum supported chunk size? Maximum?"

4096 bytes minimum, 16 MiB maximum, must be a power of two. The
chunk size is in the header so the reader knows how to frame the
on-disk chunks.

## "Why a fixed zero nonce for AES-GCM?"

Because every chunk has a unique key derived via HKDF from the DEK
with the chunk index in the info string. "Same nonce, different
key" is fine for AES-GCM. This saves 12 bytes per chunk and
removes a whole class of nonce-reuse bugs. The full argument is
in `spec/PQF-SPEC-v1.md` §5.2.

## "How big is a PQF file's overhead vs the plaintext?"

Roughly:

- Header: ~1.2 KiB for a single-recipient unsigned file. Each extra
  recipient adds ~1200 bytes (the ML-KEM-768 ciphertext dominates).
- Per chunk: 5 bytes frame + 16 bytes AEAD tag.
- Footer: 20 bytes.
- Hybrid signature (if signed): 4691 bytes × 2 (header sig + file sig)
  = 9382 bytes.

For a 16 MiB unsigned single-recipient file with the default
64 KiB chunk size: 2 KiB header + 256 chunks × 21 bytes + 20 byte
footer ≈ 7.5 KiB overhead, or 0.05% of the plaintext.

## "Is the recipient list visible in a PQF file?"

The recipient *public-key material* is. You can tell from the file
which recipients were targeted. If you need to hide that, PQF is
not the right tool — layer a metadata-privacy system above it.
This is explicitly documented in `THREAT-MODEL.md` as out of
scope.

## "What's the relationship to NIST's PQ standards?"

PQF uses ML-KEM-768 (FIPS 203) and ML-DSA-87 (FIPS 204), both
standardized by NIST in 2024, combined via X-Wing
(draft-connolly-cfrg-xwing-kem). PQF does not invent new primitives,
and as of spec v0.4.0 does not maintain its own KEM combiner — X-Wing
is the standardized hybrid construction with external IND-CCA proofs
in ROM/QROM. The contribution is the wire format around it.

## "I found a bug / want to report a vulnerability"

For non-security bugs, file an issue using the
[bug template](https://github.com/systemslibrarian/PostQuantum.FileFormat/issues/new?template=bug.yml).
For exploitable issues, use the [private security advisory
channel](https://github.com/systemslibrarian/PostQuantum.FileFormat/security/advisories/new)
described in [`SECURITY.md`](../SECURITY.md). Response-time
expectations are in [`MAINTAINERS.md`](../MAINTAINERS.md).
