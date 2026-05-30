# Claims and Evidence

Every public security claim PQF makes, paired with the artifact that
backs it. Reviewers should be able to walk this table top to bottom
and either accept each row or open a focused issue on a specific
gap.

The format is intentionally narrow: claim → assumption → evidence →
gap. "Gap" is what would be needed to upgrade a claim from
"asserted" to "proven."

## Format-level confidentiality

| Claim | Assumption | Evidence | Gap |
|---|---|---|---|
| **Confidentiality holds if X25519 OR ML-KEM-768 remains unbroken.** | The hybrid combiner is X-Wing (draft-connolly-cfrg-xwing-kem), which has IND-CCA proofs in ROM and QROM. | Spec §2.4; reference impl `Crypto/XWingKem.cs`; Rust reader `reader.rs` recipient-trial; Barbosa et al. (2024) "X-Wing" paper. | None at the combiner layer (X-Wing has external proofs). End-to-end PQF stack is not yet formally modeled. |
| **Per-chunk AEAD keys are unique.** | HKDF-Expand with the chunk index in the info string produces distinct keys per chunk. | Spec §5.2; reader and writer both bake the chunk index into the info string. | Symbolic model does not yet cover the per-chunk derivation. |
| **Fixed zero AES-GCM nonce is safe.** | Each chunk key is used exactly once. | Spec §5.2 rationale; tested by `EncryptDecryptRoundtripTests`; cross-checked by the Rust reader. | None considered open; the construction follows NIST SP 800-38D's nonce-uniqueness rule trivially because of the per-chunk key. |

## Format-level integrity

| Claim | Assumption | Evidence | Gap |
|---|---|---|---|
| **Any bit-flip in a chunk is refused.** | AES-GCM tag verification is correct in the underlying primitive. | Property-based test `Any_single_bit_flip_in_ciphertext_is_refused` (FsCheck.Xunit, 20 random cases). Negative test vectors TV-NEG-008/015/016/017. | None. |
| **Truncation at any offset is refused.** | Footer reconciliation + per-chunk tag check. | Property-based test `Truncation_at_any_offset_is_refused`; smoke test runs a truncate-and-refuse path on every PR. | None. |
| **Chunk reorder / splice / cross-file replay is refused.** | AAD is bound to `file_id || chunk_index || is_final`. | Spec §5.2; covered structurally by the AAD binding; not yet explicitly fuzzed. | A targeted refusal vector for "chunks from two different files spliced together" would tighten this. |
| **Unknown header fields are refused.** | Closed CBOR schema + deterministic re-encode check. | Spec §4.3 normative refusal rule; reader implementation `HeaderCborReader.cs`. CDDL schema `spec/pqf-header.cddl` is closed. CI: `spec-validate.yml` validates every positive vector against the CDDL. | None. |
| **Non-canonical CBOR is refused.** | Deterministic CBOR validator. | `Cbor/DeterministicCborValidator.cs`. Negative test vectors TV-NEG-010. | None. |

## Format-level authenticity (signed files only)

| Claim | Assumption | Evidence | Gap |
|---|---|---|---|
| **Authentication requires BOTH Ed25519 and ML-DSA-87 to verify.** | Both halves are evaluated unconditionally. | `HybridSigner.Verify` uses bitwise `&` instead of short-circuit `&&` so both branches always run. Tested by `HybridSignerTests`. | None. |
| **Header signature covers the full header bytes.** | Spec §6.2 normative. | Both reference impl and Rust reader compute the same hash; the differential gate catches divergence. | None. |
| **File signature covers `file_id ‖ sha256(chunks) ‖ footer`.** | Spec §6.2 step 9. | Reader: `AuthenticatedModeDecryptor` and `StreamingModeDecryptor`. Writer: `PqfFileWriter`, Rust `encrypt_to_bytes_signed`. Cross-impl differential gate. | The composition is one of the spec's open review questions (`PQF-DESIGN-RATIONALE-v1.md` §11). |
| **Signed file regeneration is byte-deterministic.** | FIPS 204 deterministic-signing variant + RFC 8032 Ed25519. | `MlDsa87SignDeterministic` on `ICryptoProvider`. Test-vector regen + `git diff --exit-code` in CI. | None. |

## Implementation correctness

| Claim | Assumption | Evidence | Gap |
|---|---|---|---|
| **The reader rejects every input the spec says is malformed.** | The reader implements every MUST in the spec. | Conformance vector set (22 negative cases) under `test-vectors/v1/cases/TV-NEG-*`. Both .NET and Rust readers run them. | More vectors are always welcome; the format's "fail-closed" claim is only as strong as the coverage. |
| **Two readers see the same bytes the same way.** | Cross-impl conformance. | `rust-conformance.yml` runs the Rust reader against the static committed vectors on every PR. `differential.yml` does the same against 50 random vectors. | A third reader in a different ecosystem would tighten this further. The Python and WASM bindings reuse the Rust reader and so don't count as independent. |
| **The Rust writer's output is accepted by the .NET reader.** | Cross-impl writer correctness. | `differential-bidirectional.yml` produces 8 random files in Rust on every PR and decrypts each with the .NET reference reader. | Only unsigned files today; signed bidirectional differential is the next contribution. The Rust signing path is implemented but not yet in the CI gate. |
| **The reference implementation builds reproducibly.** | Deterministic compile + path normalization + suppressed timestamps. | `Directory.Build.props` sets `Deterministic=true`, `ContinuousIntegrationBuild` on CI, `PathMap`, SourceLink. `reproducible-pack.yml` packs twice and diffs (after normalizing NuGet's psmdcp GUID). | None for the published `.nupkg`. Native debugging symbols are not yet reproducibly built; not a security concern but an open follow-up. |

## Parser robustness

| Claim | Assumption | Evidence | Gap |
|---|---|---|---|
| **Malformed input does not crash the parser.** | Defensive coding + tests. | Fuzz harness `tests/PostQuantum.FileFormat.Fuzz` runs the CBOR validator and streaming pipeline against random inputs. Counts every refusal; flags any non-refusal exception as a finding. Smoke pass in CI; local 10-second pass yields 55K iterations with 100% clean refusals. | OSS-Fuzz onboarding is the next step. |
| **Malformed input does not exhaust resources.** | Hard caps on header (≤ 1 MiB), chunk size (≤ 16 MiB + tag), and recipient list. | Spec §3 and §4 normative caps; reader implementation enforces. Stress tests exercise multi-GB plaintexts and 1000-recipient containers. | None considered open. |
| **The parser does not execute attacker-controlled native code.** | Managed .NET; no `unsafe` blocks; no P/Invoke in the parser path. | Code review; CodeQL with the security-and-quality query pack runs on every PR. | None. |

## Side-channel posture

| Claim | Assumption | Evidence | Gap |
|---|---|---|---|
| **The wrapper code runs the recipient-trial in constant time over the recipient list.** | The loop iterates every recipient even after a match is found; failure to unwrap with one recipient does not branch on the failure reason. | `AuthenticatedModeDecryptor.ResolveDek` implementation; documented in `docs/SIDE-CHANNEL-POSTURE.md`. | The measurement scaffold in `RecipientTrialConstantTimeTests` does not yet gate. Baseline noise characterization is the next step. |
| **The hybrid-signature verification evaluates both halves unconditionally.** | Bitwise `&` not `&&`. | `HybridSigner.Verify` source; tested by `HybridSignerTests`. | None. |
| **PQF inherits the side-channel posture of the underlying primitives.** | This is a statement about scope, not a defense. | `docs/SIDE-CHANNEL-POSTURE.md` documents per-operation what we control vs what we inherit. | Not a gap in the claim; the *underlying* primitives are an open question. BC managed C# does not claim CT against power/EM/microarchitectural attackers. The BCL path on .NET 10+ is expected to inherit platform CT properties. |

## What PQF does NOT claim

These are out-of-scope by design. Reviewers should not score PQF on them.

- **Anonymity / metadata privacy.** The header is plaintext.
- **Forward secrecy on the recipient key.** A compromise of the
  recipient's long-term key decrypts all files ever encrypted to that
  recipient. Caller-layer ephemeral key wrapping is the mitigation.
- **Deniability.** Hybrid signatures are non-repudiable.
- **Transport security.** PQF is file-at-rest only.
- **Protection against endpoint compromise.** Once plaintext is
  released, malware on the host can read it.

These limits are documented in `docs/THREAT-MODEL.md` and called
out in the README.

## How to file a claim-vs-evidence dispute

If a claim above is wrong, or a gap is undercounted, open a
[spec-review issue](.github/ISSUE_TEMPLATE/spec-review.yml).
Concrete counterexamples are the most useful form. For exploitable
findings, use the [private security advisory
channel](https://github.com/systemslibrarian/PostQuantum.FileFormat/security/advisories/new).
