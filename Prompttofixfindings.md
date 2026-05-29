You completed a pre-review hardening pass on PQF (findings F1–F9). Now implement 
the fixes. The goal is not just "close the findings" — it's to make this repo 
something a CFRG/Boneh-tier reviewer would call exemplary for an experimental 
spec-first project. Closing F1–F9 gets it to ~8.5. The last 1.5 is in the 
"10/10 bar" section below.

GROUND RULES (unchanged):
- Show every change as a diff for approval BEFORE committing. Nothing commits 
  without my sign-off.
- Do NOT change the wire format or parameter choices.
- Spec is source of truth; if implementation and spec disagree, fix toward spec.
- Honesty over polish. Disclosed limits are the credibility engine — sharpen 
  them, never soften or hide them.
- No invented citations, no claimed test results you didn't actually run, no 
  "secure" assertions beyond what the code supports.

DESIGN DECISION (this answers your closing question — treat as final for v1):
For v1 we deliberately rest "secure if either half holds" on ML-KEM-1024's FO 
ciphertext binding PLUS the per-recipient wrap-AEAD substitution check. We are 
NOT adopting X-Wing's explicit ct/pk binding in v1. Full X-Wing-parity binding 
is a documented v1.1 roadmap item, not a v1 change. Therefore F2 is 
documentation-only. Add a v1.1 roadmap entry so the deferral is on record.

IMPLEMENT IN THIS ORDER (sequenced by credibility risk, not by finding number):

1. F3 — PRIORITY. Rewrite the truncation STRIDE rows in THREAT-MODEL.md to your 
   signed-vs-unsigned versions. State plainly that unsigned whole-payload 
   erasure-to-empty is NOT mitigated. Add Open Question §11.7 if it doesn't 
   exist and cross-reference it. This is the one place the docs are currently 
   wrong — fix it first.

2. F2 — Add your Rationale §2.5 deviation paragraph verbatim (re-read for 
   accuracy first). Then locate every occurrence of the 
   "aligned with draft-ounsworth-cfrg-kem-combiners" claim and soften to 
   "follows the concatenate-then-extract pattern of [draft], with the binding 
   deviations noted in §2.5." Grep the whole repo for that phrasing — it may 
   appear in more than one file. Add the v1.1 X-Wing-parity roadmap entry.

3. F1 — Add the nonce-reuse-impossibility paragraph to the spec/rationale at the 
   chunk-cipher section. Verbatim as drafted unless re-reading the code surfaces 
   an inaccuracy.

4. F7 — Correct the MustUseReturnValue attribution in THREAT-MODEL.md to your 
   drafted text (point at StreamingModeDecryptor.DecryptAsync, note 
   ReadTrailerAsync throws).

5. F6 — Add the parameter-set conformance note to spec §2. Confirm a v1 reader 
   actually refuses a non-conformant alg.kem/alg.sig string before committing 
   the normative claim — if the refusal path isn't already there and tested, 
   flag it rather than claiming it.

6. F8 — Add the single bold "do not trust streamed plaintext until final verify" 
   line to the README streaming bullet and docs/STREAMING.md.

7. F9 — Add the "must never ship enabled" note to the test-only deterministic 
   randomness / SignDeterministic path. While there: verify there is genuinely 
   no public/release code path that reaches InjectableRandomness or 
   SignDeterministic, and add a test that asserts this if one doesn't exist.

8. F5 — Implement the read-fill loop (ReadAtLeastAsync with 
   throwOnEndOfStream:false) so non-final chunks are always full. Add a 
   regression test using a deliberately-short-reading Stream (e.g. a wrapper 
   that returns 1 byte per ReadAsync) proving non-final chunks now equal 
   chunk_size. Add the README "Current implementation limits" note only if any 
   residual limitation remains after the fix; if the fix fully resolves it, 
   instead remove it from the limits list and note the fix in PHASE-NOTES.

9. F4 — Generate the eight missing negative vectors (TV-NEG-023…) against the 
   existing writer/identities: unknown-field ×4 (top/alg/recipients/signer), 
   alg-mismatch, missing-required-field, empty-recipients, created-malformed, 
   chunk_size-invalid, binary-field-length, duplicate-cbor-key. Add manifest 
   entries with reasons. Then confirm BOTH the .NET reader and (if present) the 
   conformance harness refuse each one. Update SPEC-CHECKLIST.md so every MUST 
   maps to at least one portable vector, not just an in-tree test.

THE 10/10 BAR (do these after F1–F9, each as its own reviewable step):

A. Spec/impl drift guard. The project's whole pitch is "spec wins." Add or 
   confirm a CI check that fails if the implementation diverges from committed 
   test vectors, and document in the README how an external implementer runs 
   the conformance suite. A spec-first repo that can't be independently checked 
   isn't actually spec-first.

B. Version/draft hygiene. Spec is draft v0.3.1 with no tagged release. Before 
   sending to reviewers, propose a clean draft tag (e.g. spec-v0.4 reflecting 
   these changes) and a CHANGELOG entry summarizing F1–F9 + A. Don't tag without 
   my approval, but draft it.

C. A one-page SECURITY-OVERVIEW for reviewers. Reviewers shouldn't have to 
   reverse-engineer the threat model from three files. One page: what PQF 
   guarantees, what it explicitly doesn't, the named deviations from X-Wing/CFRG, 
   the open questions, and where to start reading. This is the document you 
   actually hand to Schneier/CFRG — make it the front door.

D. Reproducibility. Confirm the test vectors are regenerable from a documented, 
   pinned command, and that the deterministic-injection path used to make them 
   is clearly fenced off from production (ties to F9). A reviewer who can't 
   regenerate the vectors can't trust them.

DELIVERABLES:
- Diffs grouped by finding/item, in the order above, each independently 
  approvable.
- For F4/F5/F9: the new/changed test files and proof they pass (actual run 
  output, not asserted).
- A final updated findings table showing each item RESOLVED / DEFERRED-to-v1.1 
  / NEEDS-DECISION.
- A revised reviewer-readiness verdict and a fresh "one question that would most 
  change your assessment," since the X-Wing question is now answered.

Stop and ask me before: tagging anything, changing any normative MUST, or if 
implementing a fix reveals the spec itself (not just the impl) is wrong.