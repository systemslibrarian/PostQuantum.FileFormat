# Contributing to PQF

PQF is a draft cryptographic specification with a reference .NET implementation.
Contributions are welcome from cryptographers, format reviewers, .NET
implementers, second-language implementers, and writers.

This file is a contribution map, not a wall of policy. Please skim it before
opening a PR or issue.

---

## Where contributions land

PQF is **spec-first**. The normative source of truth is
[`spec/PQF-SPEC-v1.md`](spec/PQF-SPEC-v1.md). Where the implementation and the
spec disagree, the spec wins. Most contributions fall into one of these tracks:

| Track | Primary file(s) | Open as |
|---|---|---|
| Cryptographic review of the spec | `spec/PQF-SPEC-v1.md`, `spec/PQF-DESIGN-RATIONALE-v1.md` | Discussion (preferred) or Issue |
| Spec wording / clarity / typo | `spec/PQF-SPEC-v1.md` | Issue or PR |
| Conformance gap (impl accepts what spec refuses, or vice versa) | depends — start in Issue | Issue with reproducible test vector |
| Reference implementation bug | `src/PostQuantum.FileFormat/**` | Issue or PR with failing test |
| CLI bug / UX | `cli/PostQuantum.FileFormat.Cli/**` | Issue or PR |
| New negative test vector | `tests/PostQuantum.FileFormat.TestVectors/**` | PR |
| Second-language implementation | external repo, please link from a Discussion | Discussion |
| Security-sensitive (exploitable) | see [SECURITY.md](SECURITY.md) | Private advisory |

If you are not sure where something belongs, open a Discussion first.

---

## Reviewing the spec

The most valuable contribution at this stage is a critical pass over the
following normative sections:

- **§2.4** — Hybrid KEM combiner construction (HKDF salt/IKM layout, label binding).
- **§5.2** — Per-chunk AEAD construction and AAD binding (`file_id || chunk_index || is_final`).
- **§6.2 step 9** — File-signature coverage composition (`file_id || sha256(chunks) || footer`).
- **§6.3 step 7** — ML-KEM implicit-rejection / constant-time recipient trial.
- **§6.4** — Authenticated vs Streaming Mode failure-signaling contract.
- **§8.4** — Fail-closed master refusal list.

You do not need to review the whole document. A single section critique is
welcome. Reproducible refusal cases (a byte sequence that the spec says MUST be
refused, or that should be refused but currently isn't) are especially useful —
they go straight into the negative test-vector set.

Please file spec-review feedback as a Discussion (so threading works) and
reference the section number in the title.

---

## Making code changes

### Prerequisites

- .NET 8 SDK (the build target). The packed CLI rolls forward to .NET 9 / 10
  at runtime via `<RollForward>Major</RollForward>`.
- `bash` (for the smoke script).

### Build, test, smoke

```bash
dotnet restore PostQuantum.FileFormat.sln
dotnet build   PostQuantum.FileFormat.sln -c Release --no-restore
dotnet test    PostQuantum.FileFormat.sln -c Release --no-build
bash scripts/smoke.sh
```

`scripts/smoke.sh` is the same end-to-end roundtrip CI runs. It generates
keys, encrypts and signs a sample, decrypts in Authenticated Mode, verifies
the SHA-256 of the output, and verifies that a truncated container is
refused. If `smoke.sh` fails locally, do not open a PR.

### What CI enforces

- Unit tests must pass (`dotnet test`, all projects).
- The smoke script must pass.
- The packed CLI must `--help` and roundtrip on .NET 8, 9, and 10 runtimes.

There is no formal style enforcement beyond the repo's existing analyzers.
Match the surrounding code's tone.

### Pull-request checklist

- [ ] Spec is unchanged, OR the spec change is the point of the PR (and the
      change log at the top of `spec/PQF-SPEC-v1.md` is updated).
- [ ] Behavior change is covered by a test in
      `tests/PostQuantum.FileFormat.Tests/`.
- [ ] If the wire format changed, a test vector is added to
      `tests/PostQuantum.FileFormat.TestVectors/` and `SPEC-CHECKLIST.md` is
      updated.
- [ ] `scripts/smoke.sh` passes locally.
- [ ] Commit messages describe *why*, not just *what*.

### What gets rejected

- Permissive parsing (accepting input the spec requires to be refused) —
  even with a flag.
- Negotiation, downgrade paths, or "fallback" modes for any algorithm.
- Catch-all exception handlers that turn cryptographic failures into
  best-effort behavior.
- Removing a refusal path without a corresponding spec amendment.

These are not stylistic preferences; they would change the format's security
properties.

---

## Reporting bugs

Please include:

- The PQF version (`pqf --help` prints it via the assembly metadata, or check
  the csproj `<Version>`).
- The .NET runtime version (`dotnet --info`).
- A minimal reproduction. For wire-format issues, attach the offending bytes
  (or a script that produces them); for code issues, attach a failing test.
- The expected behavior, with a citation to the spec section if relevant.

For exploitable issues, follow [SECURITY.md](SECURITY.md) instead of opening a
public issue.

---

## Code of conduct

Be technical, be specific, be kind. Disagreements about cryptographic
constructions are welcome and expected; ad-hominem is not. Maintainers reserve
the right to lock or remove threads that drift away from the technical
substance.
