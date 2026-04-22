# ChatGPT Notes

Date: 2026-04-22

## Repo review

Short version: this is a serious repo. It reads like someone is trying to build a real cryptographic format, not just ship a demo with scary words in the README.

What stands out positively is the discipline. The project is clearly spec-first, and that is not just branding: the normative center is `spec/PQF-SPEC-v1.md`, the rationale exists separately in `spec/PQF-DESIGN-RATIONALE-v1.md`, conformance is enumerated in `SPEC-CHECKLIST.md`, and the implementation/docs keep saying "spec wins" instead of letting code drift into de facto truth. That is the right shape for a format project.

The repo also does a good job of fail-closed thinking: strict parsing, refusal-oriented tests, a real smoke script in `scripts/smoke.sh`, CI that checks both normal tests and runtime behavior across .NET 8/9/10 in `.github/workflows/ci.yml`, and unusually honest security disclosure in `README.md`, `SECURITY.md`, and `docs/SIDE-CHANNEL-POSTURE.md`. That honesty matters. Most early crypto repos fail there.

The main reason I take it seriously is that the repo now shows evidence of adversarial self-review, not just implementation effort. The docs openly surface unresolved questions instead of hiding them, and the recent hardening work fixed exactly the kinds of things competent reviewers flag: secret lifetime on heap copies, fail-closed filesystem behavior, strict key-file parsing, constant-iteration recipient trial, and non-short-circuit hybrid verification. That puts it ahead of most experimental crypto repos, which usually have clean prose and sloppy edges.

## Strengths

- Spec-first structure is real, not performative.
- Clear separation between normative spec, rationale, implementation, CLI, and tests.
- Fail-closed posture appears throughout docs, parser behavior, tests, and CLI behavior.
- CI meaningfully checks behavior, including smoke and runtime roll-forward, not just compilation.
- Security posture is unusually honest about limitations and unresolved questions.
- Recent hardening work addressed implementation-hygiene issues that good reviewers actually care about.

## Main weaknesses

- No external cryptographic review yet. That is still the biggest credibility gap.
- PQ primitives currently ride on managed BouncyCastle implementations, which limits any strong side-channel posture claim.
- No second implementation yet, so interoperability is still spec plus one codebase rather than true multi-implementation validation.
- The validator still works on a fully materialized buffer, so streaming validation remains unfinished.

None of those are embarrassing flaws; they are the normal reasons a careful reviewer would still say "good work, still not ready to trust with important data."

## Overall assessment

For a pre-1.0, pre-audit cryptographic format project, this repo is in unusually good shape. It is not pretending to be more mature than it is, and that alone puts it above most of the field.

If I were a cryptographer landing on it cold, I would think: "the author is serious, technically self-aware, and worth engaging." I would not think: "this is production-ready," but I also would not dismiss it as amateur theater.

## Highest-leverage next steps

1. Get one credible external cryptography review, even if it is narrow and only covers the combiner, signature coverage, and recipient-trial posture.
2. Produce a second-language reader/writer from the spec and run committed vector interoperability against it.
3. Replace or supplement the current PQ primitive provider story with something that gives a stronger side-channel posture than managed BouncyCastle on a JIT runtime.