<!--
Thanks for your interest in PQF.

Before opening this PR, please confirm:

- This change does not modify the wire format. Wire-format changes go through
  a spec PR first (against `spec/PQF-SPEC-v1.md`) and require a corresponding
  bump to the draft version.
- If this changes a refusal path, you have added or updated a negative test
  vector under `tests/PostQuantum.FileFormat.TestVectors`.
- If this changes user-visible CLI behavior, you have updated `cli/README.md`
  and the README's usage examples.
- For non-trivial changes, you have run `bash scripts/smoke.sh` locally and
  it passes.

See CONTRIBUTING.md for the full review policy.
-->

## What

<!-- One paragraph: what changed and why. -->

## Spec impact

<!--
- "No spec impact" if this is implementation-only.
- Otherwise, link the relevant section(s) of spec/PQF-SPEC-v1.md and explain
  whether the change is normative.
-->

## Test coverage

<!--
- New positive tests:
- New negative tests / refusal cases:
- Cross-impl conformance: does the Rust reader still pass?
-->

## Checklist

- [ ] No wire-format change, OR a spec PR has been merged first.
- [ ] `dotnet test` passes locally.
- [ ] `bash scripts/smoke.sh` passes locally.
- [ ] If refusal paths changed: negative vectors updated.
- [ ] If user-visible CLI changed: README + cli/README updated.
