# Streaming vs Authenticated Mode

PQF readers expose two modes for releasing plaintext. The choice has
real correctness implications — picking the wrong one is one of the
few ways a fail-closed format becomes failure-open in the caller.

**TL;DR:**

- **Use Authenticated Mode** unless you have a specific reason not to.
  It is the default for `pqf decrypt` and for `PqfDecryptor.DecryptAsync`.
- **Use Streaming Mode only when:**
  - The file does not fit in working memory, AND
  - You can guarantee the caller checks the post-stream verification
    result, AND
  - The downstream consumer can tolerate (or roll back) partial output
    if verification fails after some plaintext has been emitted.

If you can't satisfy all three, Authenticated Mode is correct.

## What each mode promises

### Authenticated Mode

- Verifies the file signature (when present) and the footer
  reconciliation **before** any plaintext byte is released to the caller.
- If verification fails, the caller sees a `PqfFileException` and
  receives zero bytes of plaintext.
- Above a threshold (currently 100 MiB), the reader stages plaintext to
  a 0600-mode `DeleteOnClose` tempfile so it can verify before
  releasing. This is a memory/disk tradeoff: above-threshold files
  cost disk-space-equal-to-plaintext during decrypt.
- The threshold is documented in `PqfStreamingPipeline` / the security
  model in [`THREAT-MODEL.md`](./THREAT-MODEL.md); it is not part of
  the wire format.

### Streaming Mode

- Releases verified chunks to the destination `Stream` as they are read.
- Each chunk's AES-GCM tag is verified before that chunk's plaintext
  is emitted — so chunk-level integrity is real.
- The footer reconciliation and the file signature (when present) are
  checked **after** the chunk stream is drained. Failures there are
  surfaced via the `PqfDecryptResult` returned by
  `PqfDecryptor.DecryptStreamingAsync` — they are not exceptions.
- The result type is decorated with `[MustUseReturnValue]` so a caller
  who forgets to check `success` / `postHocAuthenticationFailed` will
  get an analyzer warning. **A caller who discards the result has
  silently downgraded the file's authentication contract.**

## The decision matrix

| Situation | Use this mode |
|---|---|
| Default for new code | Authenticated |
| One-shot `pqf decrypt --in ... --out file.dat` | Authenticated (flag default) |
| You can fit the plaintext in memory | Authenticated |
| You're decrypting into a network socket and bandwidth matters | Streaming, with explicit failure handling |
| You're decrypting into a downstream pipe (e.g. `pqf decrypt | tar x`) | Streaming, **and** the consumer must be able to handle aborted output |
| You're producing a download to a browser | Authenticated unless the file is too large; if Streaming, abort the HTTP response on post-hoc failure (don't 200) |

## What can go wrong in Streaming Mode

### "I forgot to check the result"

```csharp
// WRONG — the analyzer will warn, and you should never silence it.
_ = await PqfDecryptor.DecryptStreamingAsync(source, destination, identity);
```

Authentication of the file as a whole is the result. Discarding the
result means you have not authenticated the file.

### "I piped to a downstream consumer that can't roll back"

If you pipe Streaming Mode output into something that side-effects on
each byte — a database, an external service, an HTTP response that
the client has already started consuming — and the post-hoc check
fails, the side effects have already happened.

**Mitigations:**

- Buffer the entire output yourself, then commit it only after the
  result is checked. (At which point you've reinvented Authenticated
  Mode.)
- Have the downstream consumer accept a "rollback signal" you can send
  on failure. Few systems support this cleanly.
- Use Authenticated Mode.

### "The tempfile threshold is too aggressive / too lax for me"

The 100 MiB threshold above which Authenticated Mode stages to disk
is a heuristic. If your environment makes it the wrong choice (e.g.
container with tiny disk; high-RAM box where tempfile is wasteful),
file an issue describing the workload — we may add a knob.

## Cross-impl behavior

The Rust reader (`impl/rust/pqf-reader`) implements only the
Authenticated-Mode semantics today. Files that fail post-hoc
verification are refused before any plaintext is returned to the
caller. If you need the Streaming Mode behavior in Rust, the streaming
release is a separate API surface to design — open an issue.

## Spec reference

- [`spec/PQF-SPEC-v1.md`](../spec/PQF-SPEC-v1.md) §6.4 — normative
  definition of both modes.
- The streaming-failure-signaling contract is one of the open spec
  questions in `spec/PQF-DESIGN-RATIONALE-v1.md` §11; refinements are
  welcome.
