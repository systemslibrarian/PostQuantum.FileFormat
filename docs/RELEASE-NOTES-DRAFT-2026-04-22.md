# Draft Release Notes

## Summary

This draft release captures the completion of the reference implementation's
Phase 4 and Phase 5 work:

- Authenticated and Streaming decryption modes
- Deterministic conformance vector generation
- Authenticated/streaming behavioral tests and manifest-based conformance tests
- A `pqf` CLI with `keygen`, `encrypt`, `decrypt`, `inspect`, and `fingerprint`

Release head verified on 2026-04-22:

- Commit: `3dd7507d9bb9e88647f9f458cd6dc3131d10f4a2`
- Branch: `main`
- CI workflow: `CI`
- CI conclusion: `success`

## Included changes

### Phase 4

- Added Authenticated Mode decryption that withholds plaintext until footer and,
  when present, file signature validation complete.
- Added Streaming Mode decryption with explicit post-hoc authentication failure
  signaling.
- Added deterministic randomness injection for test-vector generation without
  exposing test hooks in the public API.
- Added v1 conformance vectors:
  - 14 positive vectors
  - 22 negative vectors
- Added tests covering:
  - authenticated-mode roundtrip and refusal behavior
  - streaming-mode result semantics
  - manifest-driven vector conformance

### Phase 5

- Added `pqf` CLI as a thin wrapper over the library.
- Added CLI commands:
  - `keygen`
  - `encrypt`
  - `decrypt`
  - `inspect`
  - `fingerprint`
- Added CLI integration tests covering:
  - key generation
  - encrypt/decrypt roundtrip
  - inspect JSON output
  - fingerprint output
  - streaming post-hoc failure exit behavior

## Validation performed

- `DOTNET_ROLL_FORWARD=Major dotnet test PostQuantum.FileFormat.sln -c Release -v minimal`
- `DOTNET_ROLL_FORWARD=Major dotnet run --project tests/PostQuantum.FileFormat.TestVectors -- generate`
- `DOTNET_ROLL_FORWARD=Major dotnet test tests/PostQuantum.FileFormat.Tests/PostQuantum.FileFormat.Tests.csproj -c Release -v minimal --filter TestVectorConformanceTests`
- `DOTNET_ROLL_FORWARD=Major dotnet test tests/PostQuantum.FileFormat.Tests/PostQuantum.FileFormat.Tests.csproj -c Release -v minimal --filter "SignatureStructure_RefusalTests|Integration_ValidationTests|HappyPath_ValidationTests"`

## Known limitations

- The CLI package version remains `0.0.0-local`; versioning and publish metadata
  still need release-specific finalization.
- No git tag or GitHub Release has been created yet.
- The repository README still identifies external cryptographic review and a
  second-language implementation as blockers for a final `v1.0.0` release.