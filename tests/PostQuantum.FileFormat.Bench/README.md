# PQF benchmarks

BenchmarkDotNet harness for the reference implementation.

## Run all benchmarks

```bash
dotnet run --project tests/PostQuantum.FileFormat.Bench -c Release -- --filter '*'
```

Results land in `BenchmarkDotNet.Artifacts/results/`. Expect each
configuration to take roughly 1–2 minutes — BenchmarkDotNet's default
warmup + iteration policy is conservative on purpose.

## Run a specific benchmark

```bash
dotnet run --project tests/PostQuantum.FileFormat.Bench -c Release -- --filter '*EncryptDecrypt*'
dotnet run --project tests/PostQuantum.FileFormat.Bench -c Release -- --filter '*Multi*'
dotnet run --project tests/PostQuantum.FileFormat.Bench -c Release -- --filter '*HeaderParse*'
```

## What is measured

- **EncryptDecryptBenchmarks** — encrypt + decrypt throughput at 64 KiB,
  1 MiB, and 16 MiB plaintext sizes. The two numbers tell you the
  fixed-cost (header + recipient KEM) vs. variable-cost (chunked AEAD)
  split.
- **HeaderParseBenchmarks** — header parse + structural validation cost.
  This is what `pqf inspect` pays per file, with no plaintext touched.
- **MultiRecipientBenchmarks** — encrypt to N recipients, decrypt as
  the first vs. the last recipient. Encrypt is expected to scale ~linearly
  in N. The first-vs-last decrypt comparison is a coarse sanity check on
  the constant-time recipient-trial loop (the per-block KEM cost is much
  larger than any timing-channel signal, so this is informational only —
  the dudect-style measurement in `RecipientTrialConstantTimeTests` is
  the real CT instrument).

## Reproducibility

Numbers in the README are pinned to a specific machine + runtime to
make them comparable across releases. Publish your own numbers in a
PR description if they differ materially — environment matters a lot
for crypto throughput.
