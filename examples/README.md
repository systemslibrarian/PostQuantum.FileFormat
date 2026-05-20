# PQF integration examples

Small, self-contained scripts that wrap the `pqf` CLI to do something
useful. None of these are production tooling — they're meant to show
that PQF composes with familiar Unix pipelines.

If you have a real integration in mind (a backup tool, a mail
attachment, a database export), open a
[discussion](https://github.com/systemslibrarian/PostQuantum.FileFormat/discussions)
— concrete integrations are exactly what moves a format from "interesting
spec" to "thing people use."

## `pqf-encrypt-dir.sh`

Encrypts an entire directory tree to a single `.pqf` file by piping a
deterministic tar archive through `pqf encrypt`. Decryption reverses
the pipeline.

Use it like:

```bash
./pqf-encrypt-dir.sh   /path/to/dir   out.pqf   alice.pub.pem
./pqf-decrypt-dir.sh   out.pqf        /path/to/restore   alice.key.json
```

The script is intentionally short — read it before relying on it. The
tar layout is `--sort=name --owner=0 --group=0 --numeric-owner --mtime=...`
so two encryptions of the same tree produce byte-identical plaintext
inputs, which means re-encryption is reproducible up to PQF's own
randomness (KEM ciphertexts, AES-GCM nonces, etc.).
