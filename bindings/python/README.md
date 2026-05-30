# `pqf` — Python bindings

Thin pyo3 wrapper around the PQF Rust reader (`impl/rust/pqf-reader`).
Reader-only: this binding intentionally does not encrypt, sign, or
generate keys. Use the `.NET` `pqf` CLI to produce files; use this
package to consume them.

## Build

Requires Rust (stable) and Python ≥ 3.8.

```bash
cd bindings/python
pip install maturin
maturin develop --release        # installs into the active venv
# or
maturin build --release           # produces a wheel under target/wheels/
```

## Use

```python
import json
import pqf

# Read a PQF container.
with open("secret.pqf", "rb") as f:
    blob = f.read()

# Parse the header without decrypting.
header = pqf.parse_header(blob)
print(header["alg"]["kem"])           # "x25519+ml-kem-768"
print(len(header["recipients"]))
print("signed:", header["signer"] is not None)

# Decrypt with an identity loaded from the test-vector manifest.
with open("manifest.json") as f:
    manifest = json.load(f)
i = manifest["Identities"][0]
identity = pqf.Identity.from_manifest(
    i["Id"],
    i["PublicKey"],
    i["X25519PrivateKey"],
    i["MlKem768PrivateKey"],
)

plaintext = pqf.decrypt(blob, identity)
```

## Why a Python binding?

PQF is .NET-first. That's where the spec-conforming writer lives. But
the audience that decides whether a file format gets adopted —
backup-tool authors, sysadmins, data engineers, security researchers —
is largely in Python. A reader-only Python package lets them
*verify* and *consume* PQF files without taking on a .NET dependency.

## Error handling

Every refusal path in the Rust reader raises `ValueError` in Python
with the typed refusal reason in the message:

```python
try:
    pqf.parse_header(corrupt_bytes)
except ValueError as e:
    print(e)   # "MagicMismatch: header bytes do not start with PQF1"
```

## Status

Alpha. Wheels are not yet published to PyPI. Build from source for
now; PyPI publication is gated on a stable v1.0 wire-format freeze.
