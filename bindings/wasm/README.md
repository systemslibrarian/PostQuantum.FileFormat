# `pqf-wasm` — WebAssembly reader

WebAssembly build of the PQF Rust reader, packaged for browser consumption.

## Why

The Rust reader is a self-contained second-source implementation of the
PQF v1 wire format. Compiled to WebAssembly, it lets:

- A reviewer paste a `.pqf` file into a browser and see exactly what
  the spec says about it, with zero installs.
- Web tooling (transparency logs, mail clients, dashboards) verify or
  inspect PQF files without taking on a Rust or .NET dependency.
- Demos and bug reports ship a live link instead of "run this CLI."

This is a **reader-only** package. It does not encrypt, sign, or
generate keys — for that, use the `pqf` CLI.

## Build

Requires Rust (stable), `wasm-pack`, and a recent browser for the demo.

```bash
cd bindings/wasm
cargo install wasm-pack         # one-time
wasm-pack build --release --target web
```

That produces `pkg/` containing:

- `pqf_wasm.js`    — the JS shim
- `pqf_wasm_bg.wasm` — the WebAssembly payload
- `pqf_wasm.d.ts`  — TypeScript declarations
- `package.json`   — npm metadata (not yet published)

## Run the demo locally

The demo page imports `pkg/pqf_wasm.js` relative to itself. After
building:

```bash
cd bindings/wasm
python3 -m http.server 8000
# then open http://localhost:8000/demo/index.html
```

The page is intentionally minimal: drop a `.pqf`, see the header
JSON, no network calls.

## Status

Alpha. Not yet published to npm; build from source. The WASM bundle
is roughly 1.5 MB compressed (Rust crypto crates dominate) — production
deployments should reach for `wasm-opt` and code-splitting before
shipping.
