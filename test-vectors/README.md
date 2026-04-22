# Test vectors (coming)

This directory will contain the conformance test vector suite for PQF v1.

Each vector is a directory containing a `manifest.json` and binary fixture
files. See spec §9.1 and §9.1.1 for the required vector list and file format.

**Required vectors:**

- 14 positive vectors (TV-001 through TV-014) covering all mode / count /
  size combinations
- 22 negative vectors (TV-NEG-001 through TV-NEG-022) covering every refusal
  condition in spec §8.4

Vectors are generated deterministically using injected randomness seeds, so
any conforming implementation must produce byte-identical output when given
the same inputs.

See the [specification](../spec/PQF-SPEC-v1.md) §12 for authoritative detail.
