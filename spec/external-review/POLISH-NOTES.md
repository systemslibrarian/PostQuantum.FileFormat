# Spec polish notes — PQF-SPEC-v1.md

**Status:** punch list from a read-through of `PQF-SPEC-v1.md` on
2026-06-04 against PQF v1 0.6.0. Two inline fixes have already been
applied; the rest are recommendations for the author to take, leave,
or modify. None of these are wire-format changes — per §10.3 they are
"editorial clarifications" and "corrections to cross-references."

## Already fixed inline (in this branch)

- **§6.5 cost-of-trial statement** was stale: said "ML-KEM-1024
  decapsulation, one HKDF derivation." Corrected to **ML-KEM-768**
  and **SHA3-256 (X-Wing combiner)**. Pre-X-Wing leftovers from
  0.5 / earlier.
- **§11.1 Properties PQF provides table** referenced "salt" in two
  rows ("`file_id` in AAD and salt", "`recipient_index` in salt").
  X-Wing's combiner has no salt slot — these properties are
  provided by the DEK-wrap AEAD's AAD plus the X-Wing combiner's
  binding of `pk_X`. Corrected accordingly.
- **§12.1 negative vector list (P-1)** extended with TV-NEG-023
  through TV-NEG-033 (the header-schema refusal classes), each
  with its actual `RefusalReason`, plus a pointer to
  `SPEC-CHECKLIST.md` §11 and the authoritative manifest.
- **§12.2 test-vector file format (P-2)** rewritten to describe
  the actual shipped schema (single `manifest.json` per spec
  version + `cases/` dir, with `Identities[]` and `Vectors[]`
  arrays), pointing at `manifest.schema.json` as authoritative.
  The previous example (per-vector directories with their own
  manifests) was a pre-implementation sketch that the project
  outgrew.

## Recommended fixes (not yet applied)

### Medium — accuracy / completeness

#### P-3. §14.2 Barbosa et al. 2024 author list — verify

Currently reads: "Barbosa, Boyen, Connolly, Schwabe, Stehlé, Strub
(2024) — 'X-Wing: The Hybrid KEM You've Been Looking For'."

The PQF-OVERVIEW and SECURITY-CONSIDERATIONS docs I just drafted
cite a different author list (Barbosa, Boudgoust, Bouvier,
Damgård, Kaledin, Pointcheval, Renes 2024) for the IND-CCA ROM/QROM
proofs — which is what those docs need to reference. The
Connolly-Schwabe-Stehlé-Strub list is closer to the
draft-connolly-cfrg-xwing-kem author list, not the proof paper.

**Suggested fix:** verify which paper §14.2 means to cite. If it's
the IND-CCA proof paper, the author list should match what the
new SECURITY-CONSIDERATIONS doc cites. If it's a different X-Wing
paper, name the title precisely.

#### P-4. "Document history" table at the bottom is stale

§ "Document history" (lines ~1305+) shows only 0.2.0, 0.3.0, 0.3.1.
Missing 0.5.0 and 0.6.0. The top-of-document Change log has them,
so this is just a stale duplicate.

**Suggested fix:** either sync the bottom table with the top
Change log, or delete the bottom table and keep the top as the
single source. Latter is cleaner.

#### P-5. §A.1 BouncyCastle version pin

References "BouncyCastle.Crypto 2.6.2". `BouncyCastle.Cryptography`
is what the codebase actually depends on (per `dependabot.yml`'s
ignore rule and recent dep bumps). If 2.6.2 is no longer the
installed version, update; otherwise either drop the version
number (so it doesn't go stale again) or keep it as
"≥ 2.6.2" + a one-line "current pinned version in
[Directory.Packages.props](../Directory.Packages.props)" pointer.

### Low — prose / consistency

#### P-6. §11.1 "Truncation resistance" row could be tightened

Currently: "Truncation resistance | `is_final` in AAD + footer counts
+ file signature."

Consider clarifying that the three layers are AND'd for signed files
and that footer counts alone are the unsigned-file defense (which
§4.5 of the new SECURITY-CONSIDERATIONS doc spells out). A two-clause
table cell would read more naturally.

#### P-7. §13 "Known gaps" item on ML-KEM/ML-DSA youth

The wording "NIST standards finalized 2024" is fine in 2026 but
will read oddly in 2028+. Consider replacing with "Standards
finalized within the last few years" or with an absolute year
reference + commitment to revisit on each spec-version review.

#### P-8. §6.2 step 6: "Write file prefix"

The step combines several distinct on-disk fields (magic, version,
header_length, header, conditional header_signature) into one
sentence. Splitting into:

> 6a. Write magic, version, header length (10 bytes total).
> 6b. Write `header_bytes`.
> 6c. If signed: write the 4691-byte `header_signature`.

would mirror how reader-side §6.3 step 3 / step 7 already split
the same boundaries.

#### P-9. §12.3 "Spec authority"

The current paragraph is good. Consider adding the literal sentence
"In particular, where the .NET reference implementation and the
spec disagree, the spec wins." Currently this is stated in the
README but not in the spec.

#### P-10. Cross-reference §6.3 step 8

The "ML-KEM decap does NOT fail … implicit rejection" caveat in
§6.3 step 8b is a critical correctness point. Consider promoting
it to a `Note:` callout (or its own subsection) so a reader
skimming the procedure can't miss it.

## Structural suggestions (larger, optional)

#### S-1. Consider a "Reader's Guide" preface

`PQF-SPEC-v1.md` is 1300 lines. The new `spec/PQF-OVERVIEW.md`
covers some of this, but a one-page preface inside the spec itself
— "If you only have 10 minutes, read sections X, Y, Z" — would
serve readers who land directly in the spec without going through
the README.

#### S-2. Cross-link IETF draft and rationale at every section header

The IETF draft and rationale doc cover the same material at
different levels. A small "see also" footnote at each spec section
header (e.g. `## 2. Cryptographic primitives (v1)` → also
`PQF-DESIGN-RATIONALE-v1.md §2`, `draft-clark-pqf-00 §3`) would
help a reviewer triangulate, especially if they bounce between
documents on a specific question.

#### S-3. Move the IANA registry preamble

If the IETF draft ever advances, IANA registrations for
`application/pqf` and the `.pqf` extension will need to land in
the spec or the draft. They're currently in the IETF draft only.
Consider whether they should also have a placeholder section in
`PQF-SPEC-v1.md` so the spec is publicly self-contained.

---

## How to use this list

Read it once. For P-1 and P-2, decide whether to take the suggested
fix or punt with a more minimal edit. P-3 is a quick lookup. The rest
are optional; some you'll agree with, some you won't. Nothing here
affects the wire format — applying or skipping these does not produce
a v1.0.x → v1.1 bump.

If you want me to apply any specific items, point at them by number
and I'll do them in-place.
