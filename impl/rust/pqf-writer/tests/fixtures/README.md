# Test fixtures for the writer roundtrip test

These are the base64-encoded identity fields for `id-a` from
`test-vectors/v1/manifest.json`, split into one file per field so the
Rust integration test can `include_str!` them.

Regenerate when the manifest changes:

```bash
python3 - <<'PY'
import json, pathlib
m = json.loads(pathlib.Path("test-vectors/v1/manifest.json").read_text())
for ident in m["Identities"]:
    if ident["Id"] != "id-a":
        continue
    base = pathlib.Path("impl/rust/pqf-writer/tests/fixtures")
    base.mkdir(exist_ok=True)
    (base / "id-a.pub.b64").write_text(ident["PublicKey"])
    (base / "id-a.x25519.b64").write_text(ident["X25519PrivateKey"])
    (base / "id-a.mlkem.b64").write_text(ident["MlKem768PrivateKey"])
    break
print("regenerated")
PY
```

The fixtures are committed because regenerating them on every CI run
would require pulling the test-vector tooling into a Rust workspace
that today doesn't depend on it.
