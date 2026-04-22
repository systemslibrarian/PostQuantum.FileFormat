# Security Policy

## Status

**PQF is currently in DRAFT / EXPERIMENTAL status.** The specification (draft
v0.3.1) has not been reviewed by an independent cryptographer. A .NET
reference implementation and CLI are published as a `0.4.0-preview.*` release
on NuGet.org, but the wire format is not frozen and pre-`v1.0.0` files are
not guaranteed to be readable by the final v1 release. **Do not use PQF to
protect irreplaceable data.**

## Reporting security concerns

If you identify a potential issue with the PQF specification or the reference
implementation, please use one of these channels:

**For specification concerns (cryptographic construction, security
properties, or design):**
- Open a thread under [GitHub Discussions](https://github.com/systemslibrarian/PostQuantum.FileFormat/discussions) in the Security category, or
- Email paul@systemslibrarian.dev with subject line starting `[PQF-SEC]`.

**For implementation concerns (reference .NET code or CLI):**
- Open a [private security advisory](https://github.com/systemslibrarian/PostQuantum.FileFormat/security/advisories/new) (preferred for anything exploitable), or
- Email paul@systemslibrarian.dev with subject line starting `[PQF-IMPL-SEC]`.

Please do not file public issues for exploitable implementation bugs until a
fix or mitigation is available. I aim to acknowledge security reports within
72 hours.

## What counts as a security concern

Specification-level concerns (always in scope):

- Flaws in the hybrid KEM combiner (§2.4)
- Gaps in signature coverage (§6.2, §8.3)
- AEAD mode or AAD construction issues (§5.2)
- Timing or side-channel implications of the recipient-trial procedure (§6.3, §6.4)
- Fail-closed bypass paths (§8.4)
- Anything that would cause a conforming reader to accept a file a conforming
  writer should not have produced.

Implementation-level concerns (in scope for the reference .NET code and CLI):

- Memory safety, secret-material lifetime, key-file handling.
- Any deviation from the spec's MUST-level rules in the encoder or decoder.
- Parser paths that accept input the spec requires to be refused.
- Side-channel behavior that contradicts the spec's constant-time posture.

General spec feedback (clarity, readability, editorial) is also welcome but
does not require the `[PQF-SEC]` prefix — plain Discussions or Issues are
fine for that.

## Scope of responsibility

Until v1.0.0 ships, the specification may change in response to review. This
includes breaking changes. Any files produced by pre-1.0.0 implementations
may not be readable by the final v1 release.

A public record of all specification changes is maintained in the change log
at the top of `spec/PQF-SPEC-v1.md`.

## Known limitations

The reference implementation does not claim side-channel resistance. It
inherits the posture of its underlying primitives, including BouncyCastle's
ML-KEM-1024 and ML-DSA-87 implementations, which make no public claim of
constant-time execution against power, EM, or microarchitectural side
channels. The full per-operation matrix — what the wrapper controls, what it
inherits, and what is explicitly out of scope — is documented in
[docs/SIDE-CHANNEL-POSTURE.md](./docs/SIDE-CHANNEL-POSTURE.md). Reviewers
and integrators whose threat model includes co-tenancy on the same physical
CPU or physical proximity to the host should read that document before
relying on this implementation.

## Supported versions

| Version | Supported |
|---|---|
| `0.4.0-preview.*` | latest preview — security fixes land in subsequent previews |
| Older `0.x` previews | please upgrade |
| `>= 1.0.0` | not yet released |

No backports are produced for unreleased previews. Once v1.0.0 ships, this
table will be updated to reflect a long-term support policy.

## Acknowledgments

Contributors who identify specification issues will be acknowledged in the
spec's acknowledgments section (with permission). If you prefer to remain
anonymous, that preference will be honored.