# Release Preparation Runbook

## Current baseline

- Branch: `main`
- Release candidate head: `3dd7507d9bb9e88647f9f458cd6dc3131d10f4a2`
- Remote branch: `origin/main`
- CI on head: passed
- Existing git tags: none

## Release decision still needed

Before tagging, choose the external version to publish.

Open choices include:

- repository semver for the implementation, for example `v0.4.0`
- spec-aligned draft naming, for example `v0.3.1-refimpl.1`

This runbook uses `<tag>` as a placeholder to avoid creating the wrong release
identity prematurely.

## Preflight commands

Run from repository root:

```bash
git status --short
git fetch origin
git rev-parse HEAD
git rev-parse origin/main
DOTNET_ROLL_FORWARD=Major dotnet test PostQuantum.FileFormat.sln -c Release -v minimal
DOTNET_ROLL_FORWARD=Major dotnet run --project tests/PostQuantum.FileFormat.TestVectors -- generate
DOTNET_ROLL_FORWARD=Major dotnet test tests/PostQuantum.FileFormat.Tests/PostQuantum.FileFormat.Tests.csproj -c Release -v minimal --filter TestVectorConformanceTests
```

Expected result:

- clean worktree
- `HEAD == origin/main`
- tests pass
- vector generation succeeds

## Metadata to finalize before tagging

1. Replace CLI package version `0.0.0-local` in `cli/PostQuantum.FileFormat.Cli/PostQuantum.FileFormat.Cli.csproj`.
2. Decide whether to add package metadata such as repository URL, license, and
   package readme for tool publication.
3. Finalize release notes text from `docs/RELEASE-NOTES-DRAFT-2026-04-22.md`.

## Tag creation flow

Create a local annotated tag only after the metadata decision is complete:

```bash
git tag -a <tag> 3dd7507d9bb9e88647f9f458cd6dc3131d10f4a2 -m "<tag>: PQF Phase 4 and Phase 5 release candidate"
git show <tag> --stat
```

Push the tag only when ready to publish it:

```bash
git push origin <tag>
```

## Optional GitHub release publication flow

Do not run this until the tag name and release text are final:

```bash
gh release create <tag> \
  --target 3dd7507d9bb9e88647f9f458cd6dc3131d10f4a2 \
  --title "<tag>" \
  --notes-file docs/RELEASE-NOTES-DRAFT-2026-04-22.md
```

## Recommended interpretation

Given the current state, the safest next public milestone is a draft or
prerelease tag rather than a final `v1.0.0` release.