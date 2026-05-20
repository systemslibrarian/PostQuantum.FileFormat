# Interoperability matrix

A living list of tools, runtimes, and ecosystems people want PQF to
interoperate with, and the current state of each.

Open an issue to add a row, or — better — open a PR moving a row from
*Wanted* to *In progress* or *Shipped*.

## Conventions

- **Shipped** — works in CI today, covered by a test.
- **In progress** — scaffolded, not yet validated end-to-end.
- **Wanted** — no implementation yet; contributors welcome.
- **Out of scope** — explicit non-goal; will not be accepted.

## Languages and runtimes

| Target | State | Notes |
|---|---|---|
| .NET 8 / 9 / 10 (reader + writer) | Shipped | Reference implementation. Runtime matrix in CI. |
| Rust (reader) | Shipped | `impl/rust/pqf-reader`; gates `rust-conformance` CI job. |
| Rust (writer) | In progress | `impl/rust/pqf-writer`; deterministic CBOR header done, crypto operations stubbed. |
| Python (reader) | In progress | `bindings/python` pyo3 wrapper around Rust reader. Smoke-tested in CI; not yet on PyPI. |
| JavaScript / WebAssembly (reader) | In progress | `bindings/wasm` wasm-bindgen wrapper. Builds in CI; not yet on npm. |
| Go (reader) | Wanted | The KEM/sig crates exist (CIRCL); a reader is a tractable port of the Rust impl. |
| Java (reader) | Wanted | BouncyCastle has the primitives; closes the JVM gap. |
| Swift / Kotlin | Wanted | Mobile platforms; harder because of the PQ primitive availability. |

## CLI / OS distribution

| Channel | State | Notes |
|---|---|---|
| `dotnet tool install --global PostQuantum.FileFormat.Cli` | Shipped | `pqf` preview on NuGet.org. |
| Homebrew formula | Wanted | A wrapper around the dotnet-tool install path is the minimum-viable form. |
| Debian / Ubuntu .deb | Wanted | Distro packaging; requires a stable v1 first. |
| Arch PKGBUILD | Wanted | AUR submission once v1 is cut. |
| Windows winget | Wanted | Same v1 dependency. |

## Existing tools and pipelines

| Pipeline | State | Notes |
|---|---|---|
| `tar | pqf encrypt` (single-file archive of a tree) | Shipped | See `examples/pqf-encrypt-dir.sh`. |
| `pqf encrypt` as a backup-tool target (restic, borg, rclone) | Wanted | These all support pluggable encryption hooks; PQF could slot in as one. |
| Mail attachments (Thunderbird MIME) | Wanted | A small extension could register `.pqf` as an attachment type and call into a Rust/Python reader. |
| Object storage server-side scan (S3 / GCS / B2) | Wanted | A small Lambda / Function that calls `pqf inspect` on uploaded blobs. |
| Sigstore Cosign / in-toto attestation | Wanted | The PQF file_id is a natural subject; an attestation pointing to a signed PQF could chain to a transparency log. |

## Explicitly out of scope

| Item | Why |
|---|---|
| Transport (TLS, Noise, QUIC) | PQF is a file-at-rest format. Transport security lives elsewhere. |
| Real-time messaging | Same. |
| Disk / volume encryption | Same: at-rest disk encryption is a different threat model. |
| Anonymity / metadata privacy | The header is plaintext by design. Don't model PQF as solving this; layer a metadata-privacy system above. |
| Streaming network protocol (chunks released over a socket) | Streaming Mode releases verified chunks to a Stream, but the protocol surface stops at "Stream." Network framing is a caller concern. |

## How to propose an integration

Open a [discussion](https://github.com/systemslibrarian/PostQuantum.FileFormat/discussions)
describing what you want to interop with and roughly how. The bar for
moving a row to *In progress* is "there is a real PR or external repo
making the attempt."
