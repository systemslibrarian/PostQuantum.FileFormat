# PQF Pre-Review Hardening Pass — Findings Report

This report traces the PQF specification against the .NET reference
implementation. Where a claim could not be verified from the repository, it is
stated as such. No code or documentation has been changed; all proposed text
below awaits approval.

---

## Per-item analysis (requested order)

### 1. Zero-nonce AES-256-GCM — SAFE, as specified and implemented

Traced concretely:

- Payload chunk key: `ChunkCipher.EncryptChunk` → `HkdfCombiner.DeriveChunkKey`
  (`src/PostQuantum.FileFormat/Crypto/HkdfCombiner.cs:55`) =
  `HKDF-Expand(dek, "PQF1-chunk-v1" || i_BE64, 32)`. The DEK is a fresh 32-byte
  random per file (`src/PostQuantum.FileFormat/File/PqfFileWriter.cs:73`), and
  `i` is the strictly increasing chunk index. So `(chunk_key)` is unique per
  `(file, index)` pair, and the all-zero 12-byte nonce in
  `ChunkCipher` (`src/PostQuantum.FileFormat/Crypto/ChunkCipher.cs:23`) never
  sees a repeated key.
- Multi-recipient does **not** touch payload keys — the DEK is wrapped per
  recipient, payload is encrypted once. The wrap itself uses a *random* 12-byte
  nonce (`DekWrapper.Wrap`, `src/PostQuantum.FileFormat/Crypto/DekWrapper.cs:12`)
  under a per-recipient KEK, so even the wrap path has key uniqueness
  independent of nonce.
- Re-encryption generates a fresh DEK + `file_id` every call; no cross-file key
  reuse.
- Final-chunk handling: `is_final` is in AAD, not in the key — but since each
  index `i` is unique, no two chunks ever share a key regardless of the flag.

The only path that reuses a DEK is the **test-only deterministic injection**
(`InjectableRandomness`, `SignDeterministic`), used for byte-stable test
vectors. That is not reachable from the public `EncryptAsync` overload. Worth a
one-line note that this path must never ship enabled, but it is not a finding.

**Draft rationale paragraph (proposed addition to §5.2 rationale / Rationale §2):**

> *Nonce-reuse impossibility.* Every AES-256-GCM payload invocation uses a key
> of the form `HKDF-Expand(DEK, "PQF1-chunk-v1" ‖ i)`, where `DEK` is a
> uniformly random 32-byte value generated once per file and `i` is a strictly
> monotonic uint64 chunk index. Two GCM invocations therefore share a key only
> if they share both the same `DEK` (same file instance) and the same `i` (same
> chunk position) — which cannot occur within a well-formed file. Because no key
> is ever reused, the fixed all-zero nonce never produces a `(key, nonce)`
> collision, satisfying the uniqueness precondition of NIST SP 800-38D without a
> counter. Multi-recipient encryption reuses the DEK only to *wrap* it per
> recipient (distinct random nonce, distinct per-recipient KEK), never to
> re-encrypt payload.

This is the strongest part of the design. A reviewer will accept it.

---

### 2. Hybrid KEM combiner — binding is weaker than X-Wing; "secure if either half holds" is plausible but rests on an unstated dual-PRF assumption (Medium)

Construction (`HkdfCombiner.DeriveKek`,
`src/PostQuantum.FileFormat/Crypto/HkdfCombiner.cs:11`):

```
PRK = HKDF-Extract(salt = "PQF1-combiner-v1" ‖ file_id ‖ recipient_index_BE32,
                   IKM  = ss_x25519 ‖ ss_mlkem)
KEK = HKDF-Expand(PRK, "PQF1-kek-v1", 32)
```

Two things a CFRG-tier reviewer will raise:

1. **No public-key / ciphertext binding in the KDF.** X-Wing folds the X25519
   ephemeral public key *and* the recipient X25519 public key into the hash
   (`SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ label)`) precisely because X25519's
   raw shared secret is *not* contributory/binding. PQF binds neither
   `classical_epk` nor `pqc_ct` nor the recipient public keys into the KDF.
   ML-KEM's own FO transform makes `ss_mlkem` commit to `pqc_ct`, so the PQ half
   has implicit ciphertext binding; the **X25519 half does not**. The
   wrapped-DEK AEAD (AAD = `file_id`) does catch a *substituted* `classical_epk`
   (the KEK changes, the GCM tag fails), so practical substitution is detected —
   but the combiner does not achieve the LEAK-BIND-K-CT / MAL-BIND properties
   X-Wing was designed to provide. This is a real deviation, not a bug.

2. **Public salt + secret IKM is a dual-PRF posture, not a plain-HKDF posture.**
   Here the salt is fully public and both secrets are in the IKM. The claim
   "output is pseudorandom if *either* `ss_x25519` *or* `ss_mlkem` is unknown"
   requires HMAC-SHA256 to behave as a PRF when the *message* (not the key)
   carries the entropy — i.e. the dual-PRF assumption — or a ROM argument. The
   spec already disclaims a formal proof (§2.4) and lists this as open question
   #2, which is the honest move. But the rationale currently asserts the
   construction is "aligned with draft-ounsworth-cfrg-kem-combiners"; that
   draft's nominal combiner concatenates secrets as IKM with the *KEM
   ciphertexts* also bound in. PQF omits the ciphertext binding, so "aligned
   with" slightly overstates the correspondence.

**Why it matters:** Neither point breaks the "secure if either holds" claim
under standard assumptions, but a reviewer will want the deviation from
X-Wing/CFRG named explicitly rather than implied as conformance. The cheapest
fix that doesn't touch the wire format is documentation; a stronger fix (binding
`pqc_ct` and `classical_epk` into `info`) *would* be a wire change and is not
proposed here.

**Proposed rationale text (Rationale §2.5, append):**

> *Relationship to X-Wing and explicit binding.* PQF's combiner concatenates the
> two shared secrets as HKDF IKM and binds `file_id ‖ recipient_index` into the
> (public) Extract salt. It does **not** bind the KEM ciphertext (`pqc_ct`) or
> the X25519 ephemeral public key (`classical_epk`) into the KDF input, unlike
> X-Wing, which hashes `ct_X ‖ pk_X` to compensate for X25519's lack of
> shared-secret/ciphertext binding. PQF relies instead on (a) ML-KEM-1024's FO
> transform, which already makes `ss_mlkem` commit to `pqc_ct`, and (b) the
> per-recipient DEK-wrap AEAD with `file_id` as AAD, which rejects any recipient
> block whose `classical_epk` was substituted (the derived KEK changes and the
> GCM tag fails). As a consequence PQF does **not** claim the formal
> MAL-BIND-K-CT binding properties of X-Wing; it claims only IND-CCA "secure if
> either KEM half holds," and only under the dual-PRF treatment of HKDF-Extract
> with a public salt. A formal proof of the assembled construction has not been
> produced. (Open question §11.2.)

**Open decision for the author:** is matching X-Wing's binding (and thus its
security proof) a v1.1 goal, or is the at-rest "wrap-AEAD catches substitution"
argument sufficient for the threat model? That answer changes whether this is a
doc note or a deferred wire change.

---

### 3. Hybrid signature — fails closed correctly; scope is correct; one disclosed domain-separation gap (Low / disclosed)

- `HybridSigner.Verify` (`src/PostQuantum.FileFormat/Crypto/HybridSigner.cs:48`)
  computes both halves and combines with bitwise `&` (not `&&`), so it is
  non-short-circuiting and refuses if *either* half fails. Length is hard-checked
  to 4691 before any verify. No partial-verify path.
- Both call sites refuse on `false`: `AuthenticatedModeDecryptor`
  (`src/PostQuantum.FileFormat/File/AuthenticatedModeDecryptor.cs:34`) (header
  sig before any decryption) and again on the file signature before draining the
  staging buffer; `StreamingModeDecryptor`
  (`src/PostQuantum.FileFormat/File/StreamingModeDecryptor.cs:37`) verifies the
  header sig up front and returns a failure `Result` on the post-hoc file sig.
- Scope matches spec: file sig covers `file_id ‖ sha256(on-disk chunk bytes) ‖
  footer(20)` — see writer
  (`src/PostQuantum.FileFormat/File/PqfFileWriter.cs:170`) and both decryptors
  reconstruct it identically. The chunk hash is over frame bytes (5-byte prefix
  + ciphertext+tag) in both writer and reader, so coverage is byte-consistent.
- **Disclosed gap:** header-sig and file-sig messages share one signing key with
  no domain-separation prefix (Rationale §11.6). The two messages are
  structurally distinct (CBOR map vs. 68-byte `file_id‖hash‖footer`), so no
  concrete cross-protocol replay was found, but it is correctly flagged as open.
  No new finding.

No partial-verify or downgrade path found. `alg` strings are exact-match
enforced and (when signed) covered by the header signature, so intra-v1
downgrade is blocked.

---

### 4. AAD / binding — reorder/splice/partial-truncation all prevented; one truncation edge the threat model overclaims (Medium — see #7)

- AAD = `file_id ‖ chunk_index_BE64 ‖ is_final` (`ChunkCipher.BuildAad`,
  `src/PostQuantum.FileFormat/Crypto/ChunkCipher.cs:78`). Reorder → wrong
  `chunk_index` in AAD → tag fail. Cross-file splice → wrong `file_id` → tag
  fail. Flipping a chunk's on-disk `is_final` flag → AAD mismatch → tag fail.
  All sound.
- Truncation: the pipeline tracks `sawFinal` and **refuses** if it hits the
  footer with `index > 0` before seeing a final-flagged chunk
  (`src/PostQuantum.FileFormat/File/PqfStreamingPipeline.cs:191`), and refuses if
  the stream EOFs without a final flag. So dropping a *suffix* of a multi-chunk
  file is caught even if the attacker rewrites the footer count — the surviving
  last chunk is not flagged final.
- **The edge:** removing *all* chunks and rewriting the footer to
  `chunk_count=0, plaintext_bytes=0` yields a structurally valid **empty file**.
  The `index==0` branch treats `PQFE`-at-position-0 as a legitimate empty file.
  On **unsigned** files (footer unauthenticated) this is indistinguishable from
  a real empty file. It does not let an attacker keep a chosen non-empty prefix
  (any surviving chunk trips the final-flag check), so the exposure is "erase
  payload to empty," and unsigned files carry no authenticity anyway — but it
  contradicts the threat model's unconditional "Truncation … Mitigated / 
  truncation that loses a chunk fails the count check." The count check only
  catches truncation when the footer is *not* also rewritten, which is only
  guaranteed for signed files. This belongs in #7.

The footer counter / `is_final` cannot be used to silently drop *trailing*
chunks of a multi-chunk file — confirmed. The only silent case is whole-payload
erasure on unsigned files.

---

### 5. Fail-closed parsing — every §8.4 MUST has an in-tree refusal test; the portable negative-vector set is a strict subset (Medium)

Determinism: `DeterministicCborValidator.ParseStrict` rejects non-shortest
ints, indefinite-length, duplicate keys, out-of-order keys, floats, and trailing
bytes — confirmed by `HeaderParser_RefusalTests`
(`tests/PostQuantum.FileFormat.Tests/File/HeaderParser_RefusalTests.cs:52`, 7
cases). The README/checklist claim option (a) "native enforcement" — this
matches the code. The "re-encode and compare" alternative is not what is
implemented, but the spec permits either, so this is conforming.

In-tree refusal coverage is comprehensive — `HeaderSchema_RefusalTests`
(`tests/PostQuantum.FileFormat.Tests/File/HeaderSchema_RefusalTests.cs:9`)
covers missing-alg, unknown-field, wrong/too-small chunk_size, created-without-Z,
file_id length, empty recipients, recipient field length, wrong kem string. So
**no §8.4 MUST is untested in the .NET suite.**

The gap is in the **portable cross-implementation negative vectors**
(`test-vectors/v1/`, the set the Rust second-source reader is gated against).
Those 22 `TV-NEG-*` vectors cover only: Magic, Version, Truncation, TrailingData,
FooterMagic, ReservedFlagBits, ChunkLengthExceedsRemaining, AeadTag,
SignatureVerification, NonDeterministicCbor, HeaderLengthExceedsLimit,
FooterChunkCountMismatch, FooterPlaintextBytesMismatch, IdentityMatchesNoRecipient.

**No portable negative vector exists for these MUSTs** (only in-tree C# tests):

- Unknown field at top level / inside `alg` / `recipients[*]` / `signer` (§4.3 —
  four distinct MUSTs)
- Algorithm-identifier mismatch (§4.2.1)
- Missing required field (§6.3 step 4)
- Empty `recipients` array (§8.4)
- `created` malformed / non-UTC (§8.4)
- `chunk_size` invalid (§6.3 step 6)
- Binary field length mismatch (§4.2.2)
- Duplicate CBOR key (a `DuplicateCborKey` reason exists but no `TV-NEG` carries it)

**Why it matters:** an independent implementer validating conformance against the
published vector set would *not* be forced to implement these refusals. That
undercuts the "complete enough for independent implementation" goal (§1.2). The
fix is additive (new vectors), not normative.

**Proposed:** add `TV-NEG-023…` vectors for the eight classes above and mark
them in the manifest. These can be generated against the existing
writer/identities on request (not yet committed).

**Status (2026-04-22):** the generator now emits `TV-NEG-023…TV-NEG-033` for
all of the classes above (unknown-field ×4, alg-mismatch, missing-field,
empty-recipients, created-malformed, chunk_size, binary-field-length, and
duplicate-CBOR-key). See `tests/PostQuantum.FileFormat.TestVectors/Program.cs`
(the `MutateHeader`/`AddNestedMapField`/`DuplicateChunkSizeKey` helpers). Each
class is also mapped to its portable vector in `SPEC-CHECKLIST.md` §11. The
`manifest.json`/`cases/*.pqf` artifacts and the Rust conformance pass land only
after the `PostQuantum.FileFormat.TestVectors` project is re-run — that
regeneration is still pending (terminal execution unavailable in this session),
so the committed manifest still lists 22 negatives until then.

---

### 6. Streaming mode — post-hoc failure is surfaced via a `MustUseReturnValue` `Result`; one doc inaccuracy (Low)

- `StreamingModeDecryptor.DecryptAsync`
  (`src/PostQuantum.FileFormat/File/StreamingModeDecryptor.cs:13`) is annotated
  `[MustUseReturnValue]` and returns `PqfDecryptResult(success, reason, emitted,
  postHocAfterEmit)`. Footer mismatch and file-sig failure return `success=false`
  with the bytes-already-emitted flag set. Per-chunk AEAD failure also returns
  failure before emitting that chunk. This satisfies the §6.4.2 "impossible to
  overlook" contract via a must-check return.
- **Inaccuracy to fix:** the threat model says the attribute is on
  *"`PqfStreamingPipeline`'s trailer method."* It is actually on
  `StreamingModeDecryptor.DecryptAsync`; `PqfStreamingPipeline.ReadTrailerAsync`
  returns a plain `Task` (it throws `PqfFileException` on failure, which is also
  a non-silent path, but it is not the `MustUseReturnValue` carrier). Tighten the
  wording so a reviewer reading the code does not catch the doc being wrong about
  its own enforcement point.
- Docs: the README "Streaming Mode" bullet and `docs/STREAMING.md` carry the
  warning, but the **strongest** warning ("do not trust streamed plaintext until
  final verify") is split across the spec and rationale. Recommend a single bold
  line in the README streaming bullet. Minor.

**Proposed THREAT-MODEL.md edit:**

> - The streaming-mode contract requires the caller to consume the trailing
>   result. This is enforced at the API level by a `[MustUseReturnValue]`
>   attribute on `StreamingModeDecryptor.DecryptAsync`, whose `PqfDecryptResult`
>   carries an explicit post-hoc-failure flag; the underlying
>   `PqfStreamingPipeline.ReadTrailerAsync` additionally throws on
>   footer/structure failure.

---

### 7. Threat model / metadata — good already; two overclaims to sharpen (Medium)

The plaintext-header leakage is well disclosed (README "Metadata is visible,"
THREAT-MODEL "Information disclosure — header metadata: Out of scope"). What an
adversary learns is essentially complete, but the *list* should be made explicit
and tied to the decades-confidentiality pitch:

**Proposed THREAT-MODEL.md addition (new subsection under "What PQF deliberately does NOT promise"):**

> **Exactly what the plaintext header reveals.** An observer with the raw `.pqf`
> file learns, without any key: the format and version; the full algorithm suite
> (`alg.*`); `chunk_size`; the `created` UTC timestamp; the 16-byte `file_id`;
> the number and order of recipients; each recipient's `classical_epk` (a
> per-file ephemeral, not a long-term identifier) and `pqc_ct`; and, when signed,
> the signer's long-term Ed25519 and ML-DSA-87 public keys. The signer public
> keys are stable across files and therefore link all files signed by the same
> identity. The recipient `classical_epk` is ephemeral per file, but recipient
> *count* and *ordering* are stable and may enable cross-file correlation if a
> writer preserves recipient order. For a "confidential for decades" pitch this
> means: the *contents* are protected by the hybrid KEM, but the *fact, time,
> recipient cardinality, and signer identity* of every encryption are permanently
> exposed and should be considered harvestable alongside the ciphertext.

**Two truncation/footer overclaims to correct** (consistent with #4):

The STRIDE table currently states truncation is unconditionally "Mitigated."
Proposed replacement for the two relevant rows:

> | **Tampering** — truncation (partial) | Both | `is_final` AAD binding: any surviving last chunk that is not flagged final causes refusal when the footer/EOF is reached. Dropping a suffix of a multi-chunk file is caught even if the footer count is rewritten. | Mitigated. |
> | **Tampering** — truncation to empty (whole-payload erasure) | Integrity | On **signed** files the file signature covers the footer and chunk hash, so erasure is detected. On **unsigned** files, an attacker can remove all chunks and rewrite the unauthenticated footer to `0/0`, producing a file indistinguishable from a legitimately empty one. | Mitigated when signed; **not** mitigated on unsigned files — consistent with unsigned files carrying no authenticity (see Open Question §11.7). |

This is the single place where the current docs are *wrong* rather than merely
incomplete: "truncation that loses a chunk fails the count check" is true only
when the footer is authentic.

---

### 8. Parameter consistency — scope boundary is implied, not stated (Medium, doc-only)

The spec fixes exactly ML-KEM-1024 + ML-DSA-87 (§2, "Readers that do not support
all of them MUST refuse"). Rationale §2.1 explains Cat-5 for archival and says
"For files intended for transient confidentiality… Category 3 would be
appropriate. PQF is not that tool." That is a clear scope boundary *for PQF
itself*. What is missing is an explicit statement that **ML-KEM-768 / Cat-3 is
non-conformant for PQF v1**, so a reviewer who also sees the author's ML-KEM-768
work (Meow Decoder, PrayerWarriors) understands the difference is intentional
(files-at-rest vs. interactive), not an inconsistency.

**Proposed spec §2 note (non-normative-to-normative tightening — author's call):**

> **Parameter-set conformance.** PQF v1 is defined over exactly the suite in
> §2.1–§2.4. ML-KEM-768 and ML-DSA-65 (NIST Category 3) are **non-conformant**
> for PQF v1: a v1 reader MUST refuse a header whose `alg.kem` or `alg.sig` names
> any other parameter set. This is deliberate. Category-5 parameters are chosen
> for the decade-plus *files-at-rest* horizon, where the size cost is negligible
> and the larger margin against lattice cryptanalysis is worth it. Interactive or
> transport protocols with short-lived secrets (where Category 3 is a reasonable
> choice) are out of scope for this format; selecting a parameter set is a
> per-protocol decision, and PQF deliberately fixes one suite rather than
> negotiating. Other projects by this author that target interactive use
> intentionally use Category 3 and are governed by their own specifications, not
> this one.

---

### 9. Implementation-limits sweep — one new undisclosed gap found (Medium)

Beyond the already-disclosed `OpenForValidation` int-buffer limit, one
undisclosed writer behavior was found:

**Writer assumes `Stream.ReadAsync` fills the buffer.** `PqfFileWriter`
(`src/PostQuantum.FileFormat/File/PqfFileWriter.cs:131`) reads each chunk with a
single `plaintext.ReadAsync(current.AsMemory(0, chunkSize))` and treats
`isFinal = (nextRead == 0)`. `Stream.ReadAsync` is permitted to return fewer
bytes than requested even when more data is available (common for pipes,
network, `CryptoStream`, console). On such a source the writer emits **non-final
chunks smaller than `chunk_size`**. Readers do not enforce "non-final chunk ==
chunk_size" (`src/PostQuantum.FileFormat/File/PqfStreamingPipeline.cs:218` only
bounds `16 ≤ len ≤ chunk_size+16`), so the file still round-trips — but:

- Spec §5.1 ("The plaintext is divided into chunks of `chunk_size` bytes. The
  final chunk MAY be smaller") implies non-final chunks are exactly `chunk_size`;
  the writer can violate that on non-file streams.
- It silently changes chunk granularity/size profiling and produces more chunks
  than necessary (perf + metadata).

Not a confidentiality break (keys still unique per index), but it is a
correctness/interop gap that belongs in "Current implementation limits," and
arguably the writer should use a read-fill loop. **Proposed fix (non-wire):**
replace the single read with `ReadAtLeastAsync(buffer, chunkSize,
throwOnEndOfStream: false)` so non-final chunks are always full; this is a pure
implementation fix, no format change.

**Proposed README "Current implementation limits" addition:**

> - The writer currently issues one `Stream.ReadAsync` per chunk and treats a
>   short read as a chunk boundary. On non-file sources that return partial reads
>   (pipes, sockets, `CryptoStream`), this can emit non-final chunks smaller than
>   `chunk_size`. Such files remain spec-valid and decrypt correctly, but their
>   chunk layout is not minimal. A read-fill loop is the planned fix.

Other items checked and found **clean**: chunk-hash byte order matches
writer↔reader; `chunk_size` fits in `int`; plaintext/byte counts use `ulong`;
`recipient_index` BE32 matches; empty-file path is consistent; footer byte tally
uses `ciphertext_len − 16` which equals plaintext length under GCM. No other
int/uint64 mismatches surfaced.

---

## Findings summary (by severity)

| # | Severity | What | Where | Fix type |
|---|---|---|---|---|
| F1 | Critical-adjacent (verified SAFE) | Zero-nonce GCM key uniqueness | `ChunkCipher` + `HkdfCombiner.DeriveChunkKey` | Add proof paragraph (doc) |
| F2 | Medium | Combiner omits ct/pk binding vs X-Wing; dual-PRF assumption unstated; "aligned with CFRG" overstates | `HkdfCombiner.DeriveKek`, Rationale §2.5 | Doc now; wire change only if X-Wing parity wanted |
| F3 | Medium | Threat model overclaims unconditional truncation mitigation; unsigned whole-payload erasure to empty is silent | THREAT-MODEL STRIDE rows; `PqfStreamingPipeline:191` | Tighten doc (sharpen, don't paper over) |
| F4 | Medium | Portable negative-vector set missing 8 MUST classes (unknown-field×4, alg-mismatch, missing-field, empty-recipients, created-malformed, chunk_size, field-length, duplicate-key) | `test-vectors/v1/manifest.json` | Add vectors (additive) — generator code landed (`TV-NEG-023…033`); manifest regen + Rust pass pending |
| F5 | Medium | Writer treats short `ReadAsync` as chunk boundary → undersized non-final chunks on non-file streams | `PqfFileWriter:131` | Read-fill loop + disclose |
| F6 | Medium (doc) | Parameter-set conformance boundary implied, not stated (vs ML-KEM-768 projects) | spec §2 | Add conformance note |
| F7 | Low | Threat model misattributes the `MustUseReturnValue` enforcement point | THREAT-MODEL.md | One-line correction |
| F8 | Nit | README streaming "do not trust until verify" warning could be a single bold line | README, `docs/STREAMING.md` | Wording |
| F9 | Nit | Test-only deterministic-randomness/`SignDeterministic` path should carry a "never ship enabled" note | `PqfFileWriter`, `HybridSigner` | Comment/doc |

No edits have been made — all of the above is proposed text awaiting approval.
F4 (generating vector files) and F5 (a small code change) are separate,
reviewable steps.

> **Update (2026-05-29):** the proposals above have since been implemented.
> See "Hardening-pass status (2026-05-29)" at the end of this document for the
> per-finding disposition and the verification steps that remain.

---

## Reviewer-readiness verdict

**What's solid (will survive a cryptographer's first pass):**

- The zero-nonce/per-chunk-key argument is correct and cleanly implemented — the
  headline risk is actually the strongest point.
- Fail-closed parsing is real: deterministic-CBOR enforcement, exact length/alg
  checks, reserved-bit refusal, bounded allocations, non-short-circuit hybrid
  verify, and an in-tree refusal test for every §8.4 MUST.
- The honesty posture (disclosed open questions, EXPERIMENTAL labeling, "spec
  wins") is exactly what earns credibility. Don't dilute it.

**What would embarrass you in front of a cryptographer:**

1. The threat model stating truncation is unconditionally mitigated when the
   footer is unauthenticated on unsigned files (F3). A reviewer will find the
   empty-file erasure quickly, and the *overclaim* costs more credibility than
   the gap itself.
2. "Aligned with draft-ounsworth-cfrg-kem-combiners" while omitting the
   ciphertext binding those constructions include (F2). Name the deviation
   first.
3. The portable conformance vectors not actually covering the
   unknown-field/alg-mismatch/length MUSTs (F4) — directly undercuts the
   "independently implementable" claim central to a spec-first project.

**Three things to fix before sending it out:**

1. **F3** — rewrite the truncation/footer STRIDE rows to be precise about signed
   vs unsigned (sharpen, don't soften).
2. **F2** — add the X-Wing/dual-PRF deviation paragraph to the rationale and
   soften "aligned with" to "follows the concatenate-then-extract pattern of,
   with the deviations noted."
3. **F4** — generate the eight missing negative vectors so the published
   conformance set matches the spec's MUSTs.

(F5 is worth doing too, but it is an implementation fix, not a credibility risk
in review.)

---

## The one question that would most change the assessment

**Is matching X-Wing's explicit ciphertext/public-key binding (and thereby its
formal MAL-BIND security proof) an intended v1.1 wire-format goal — or is the
"secure if either half holds" claim deliberately resting on ML-KEM's FO
ciphertext binding plus the wrap-AEAD substitution check?** This determines
whether the combiner (F2) is a one-paragraph documentation clarification or a
deferred normative change, and it is the single point a Boneh/CFRG-tier reviewer
will spend the most time on.

---

## Hardening-pass status (2026-05-29)

The edits below have now been made (compile-validated; see the per-finding
"Fix type" column above). Nothing has been committed or tagged.

| # | Disposition | Landed change |
|---|---|---|
| F1 | RESOLVED (doc) | Zero-nonce key-uniqueness proof paragraph in rationale; no code change needed (design already safe). |
| F2 | DEFERRED-v1.1 / NEEDS-DECISION | Rationale §2.5 deviation paragraph + §11.9 roadmap; "aligned with" softened to "follows the concatenate-then-extract pattern, with deviations noted." X-Wing ciphertext/pk binding is an open v1.1 wire-format question (see final question above). |
| F3 | RESOLVED (doc) | THREAT-MODEL truncation/footer STRIDE rows now distinguish signed vs unsigned; unsigned empty-file erasure disclosed. |
| F4 | CODE LANDED / REGEN PENDING | `TV-NEG-023…033` generator added (`tests/PostQuantum.FileFormat.TestVectors/Program.cs`); `SPEC-CHECKLIST.md` §11 maps every fail-closed MUST to a portable vector. Manifest/`cases/*.pqf` regen + Rust conformance pass still need the project to be re-run. **Static cross-check done:** both `HeaderCborReader` (.NET) and `impl/rust/pqf-reader/src/header.rs` + `cbor.rs` (Rust) refuse all 11 new vectors with the exact PascalCase reason the manifest declares, via matching code paths — so **no Rust source change is anticipated** (conformance count 36 → 47). This was reasoned from source, not executed. |
| F5 | RESOLVED (code) | `PqfFileWriter` uses `ReadAtLeastAsync` for non-final chunks; regression test `EncryptAsync_short_read_source_still_emits_full_non_final_chunks`. |
| F6 | RESOLVED (doc) | Spec §2 parameter-set conformance paragraph (ML-KEM-768/ML-DSA-65 non-conformant); spec bumped 0.3.1 → 0.3.2. |
| F7 | RESOLVED (doc) | `MustUseReturnValue` attribution corrected in THREAT-MODEL. |
| F8 | RESOLVED (doc) | Bold "do not trust streamed plaintext until final verification" line in README + `docs/STREAMING.md`. |
| F9 | RESOLVED (code) | `SignDeterministic` + deterministic-encrypt path now `internal`; reflection guard test `Deterministic_test_hooks_are_not_public_api_surface`. |

**Verification status:** All changes are compile-clean per the editor's
error checker. No build or test run was possible this session (terminal
execution unavailable — `ENOPRO`). The following remain to be run before the
pass can be called verified:

1. `dotnet test` for the full suite (expected: prior 130 + 2 new F5/F9 tests).
2. `dotnet run --project tests/PostQuantum.FileFormat.TestVectors` to emit
   `TV-NEG-023…033` and rewrite `manifest.json`.
3. Byte-stability check: regenerate twice, diff the `cases/` tree (expected:
   identical) and confirm the pre-existing `TV-001…022` bytes are unchanged.
4. Rust conformance: `cargo run --release --bin pqf-conformance
   --manifest-path impl/rust/pqf-reader/Cargo.toml -- test-vectors/v1`
   (expected: 36 → 47 vectors pass; the new reasons already exist in the Rust
   `RefusalReason` enum, so no Rust change is anticipated — but this must be
   confirmed, not assumed).

**Release-management proposal (DRAFT — do not tag without approval):**

- Spec: tag `spec-v0.3.2` once items 1–4 above pass. The bump is
  clarification-only (no wire/parameter/MUST change), so it is a patch-level
  draft revision, not a new format version. The wire format remains `PQF1` /
  `0x0001`.
- Reference implementation: fold these changes into the next
  `0.4.0-preview.x` line via the existing `[Unreleased]` CHANGELOG entry. No
  separate tag is proposed here.
- Do **not** cut a v1.0.0 / frozen-format tag in this pass: F2 (X-Wing binding
  decision) is still open and is the one item that could force a v1.1
  wire-format change.
