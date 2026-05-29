PQF context: spec-first, experimental, hybrid post-quantum file format. .NET 
reference impl, draft spec v0.3.1, committed test vectors. The findings pass 
(F1–F9) is handled separately — do NOT redo it. This task is the "make it a 
repo a CFRG/Boneh-tier reviewer takes seriously" layer.

GROUND RULES:
- Show every change as a diff for approval BEFORE committing. Nothing commits 
  without my sign-off. Do NOT tag a release without explicit approval.
- Do not change the wire format, parameters, or any normative MUST.
- No invented results — if you claim the conformance suite or CI passes, show 
  the actual run output. If something can't be verified, say so.
- Honesty over polish throughout.

Do these as four independently-reviewable steps:

A. RUNNABLE CONFORMANCE STORY.
   The pitch is "spec wins, independently implementable." Make that real and 
   runnable.
   - Add/confirm a CI job that fails if the implementation diverges from the 
     committed test vectors (positive + negative). Show me the workflow and a 
     passing run.
   - Add a single documented command an external implementer runs to validate 
     their own reader against the published vectors. Document it in the README 
     under a "Conformance" heading: prerequisites, the exact command, and what 
     pass/fail looks like.
   - Confirm SPEC-CHECKLIST.md maps every normative MUST to at least one 
     PORTABLE vector (not just an in-tree C# test). List any MUST that still 
     lacks portable coverage rather than papering over it.

D. REPRODUCIBILITY (ties to A).
   - Make the test vectors regenerable from one documented, pinned command. 
     Show the command and prove a regenerated set is byte-identical to the 
     committed set.
   - Confirm the deterministic-injection path used to generate vectors is 
     clearly fenced off from any production/release code path. If a test 
     asserting that fence doesn't exist, add one. A reviewer who can't 
     regenerate the vectors — or who suspects test-only determinism leaks into 
     prod — can't trust either.

C. SECURITY-OVERVIEW ONE-PAGER (the front door).
   Create docs/SECURITY-OVERVIEW.md — the single document handed to a reviewer 
   so they don't reverse-engineer the threat model from three files. One page, 
   tight, linking out for depth. Must contain:
   - What PQF guarantees (confidentiality model: secure if either KEM half 
     holds; authenticity only when signed).
   - What it explicitly does NOT guarantee (no transport security, no anonymity, 
     plaintext header / metadata visible, unsigned files carry no authenticity 
     incl. the empty-erasure case).
   - The named deviations from X-Wing/CFRG combiners and WHY (FO binding + 
     wrap-AEAD substitution check; X-Wing-parity binding deferred to v1.1).
   - The open questions, linked to their spec sections.
   - "Where to start reading" — ordered pointers into spec / rationale / 
     threat model.
   Keep it genuinely one page. Link, don't duplicate. This is the document a 
   reviewer reads first, so it sets the tone: precise, scoped, honest.

B. VERSION / DRAFT HYGIENE (do LAST, after A/C/D land).
   - Propose a clean draft tag reflecting the current hardened state (e.g. 
     spec-v0.4) and a CHANGELOG.md entry summarizing what changed since v0.3.1. 
     Draft both, but DO NOT tag without my approval.
   - Confirm README status table, spec version string, and any in-doc version 
     references are consistent post-change.

DELIVERABLES:
- Diffs grouped by step (A, D, C, B), each independently approvable.
- Actual run output for the CI job, the conformance command, and the 
  vector-regeneration byte-equality check — not asserted, shown.
- A short closing note: is this now reviewer-ready, and the single biggest 
  remaining weakness if any.

Stop and ask me before tagging anything, or if any step reveals the spec 
itself (not just docs/tooling) needs a normative change.