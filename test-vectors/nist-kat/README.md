# NIST KAT vectors

This directory is populated on demand by `scripts/fetch-nist-kat.sh` (and
its PowerShell equivalent). The NIST-published KAT files are not
committed to this repo because:

1. They are large.
2. They are authoritative artifacts published by NIST and should be
   verified against NIST checksums on each fetch rather than mirrored.
3. We do not want to subtly diverge from the upstream files.

After running the fetch script, this directory should contain at least:

- `ml-kem-768.rsp` — KAT vectors for FIPS 203 (ML-KEM-768).
- `ml-dsa-87.rsp`   — KAT vectors for FIPS 204 (ML-DSA-87).

Run the cross-check harness with:

```bash
dotnet run --project tests/PostQuantum.FileFormat.Kat
```

The harness uses the same `ICryptoProvider` the production code uses,
so a KAT failure is direct evidence of a wrapper-level defect (wrong
parameter set, byte ordering, mistaken serialization choice).

The KAT harness intentionally calls primitive APIs that may not exist
on the current `ICryptoProvider` surface (`MlKemDeriveKeyPair`,
`MlKemDecapsulate`, `MlDsaDeriveKeyPair`, `MlDsaVerify`). Wiring those
through is the second half of this work item; until then the harness
acts as a "build-the-surface" forcing function.
