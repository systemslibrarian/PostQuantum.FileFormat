# Test vectors

The v1 conformance suite is generated under `test-vectors/v1/`.

- `manifest.json` contains identity material and expected outcomes.
- `cases/TV-001.pqf` through `cases/TV-014.pqf` are positive vectors.
- `cases/TV-NEG-001.pqf` through `cases/TV-NEG-033.pqf` are negative vectors.
  `TV-NEG-023` through `TV-NEG-033` exercise the header-schema refusal classes
  (unknown field at each level, algorithm-identifier mismatch, missing required
  field, empty `recipients`, malformed `created`, invalid `chunk_size`, binary
  field-length mismatch, and duplicate CBOR map key). `SPEC-CHECKLIST.md` §11
  maps every fail-closed refusal to its portable vector.

Regenerate with:

```bash
dotnet run --project tests/PostQuantum.FileFormat.TestVectors -- generate
```

Vectors are deterministic using internal randomness injection and deterministic
signing hooks in the library.

These hooks are test-only plumbing and must never be surfaced by production
encryption APIs.
