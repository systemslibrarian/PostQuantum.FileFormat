# Test vectors

The v1 conformance suite is generated under `test-vectors/v1/`.

- `manifest.json` contains identity material and expected outcomes.
- `cases/TV-001.pqf` through `cases/TV-014.pqf` are positive vectors.
- `cases/TV-NEG-001.pqf` through `cases/TV-NEG-022.pqf` are negative vectors.

Regenerate with:

```bash
dotnet run --project tests/PostQuantum.FileFormat.TestVectors -- generate
```

Vectors are deterministic using internal randomness injection in the library.
