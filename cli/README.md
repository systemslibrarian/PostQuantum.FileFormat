# `pqf` CLI (coming)

This directory will contain the `pqf` command-line tool, distributed as a .NET
global tool.

Planned subcommands:

- `pqf keygen` — generate an identity (encryption or signing)
- `pqf encrypt` — encrypt a file to one or more recipients
- `pqf decrypt` — decrypt a file with your identity
- `pqf inspect` — display header and footer without decrypting
- `pqf fingerprint` — compute a public key fingerprint for verification

See the [specification](../spec/PQF-SPEC-v1.md) for authoritative detail.
