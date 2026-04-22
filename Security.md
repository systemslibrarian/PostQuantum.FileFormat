# Security

## Status

**PQF is currently in DRAFT / EXPERIMENTAL status.** The specification has not
been reviewed by an independent cryptographer, and no reference
implementation has been shipped. The format is not yet suitable for
protecting real data.

## Reporting security concerns

If you identify a potential issue with the PQF specification or (once
published) the reference implementation, please use one of these channels:

**For specification concerns (cryptographic construction, security
properties, or design):**
- Open a GitHub Discussion under the "Security" category, or
- Email paul@systemslibrarian.dev with subject line starting `[PQF-SEC]`

**For implementation concerns (once code exists):**
- Email paul@systemslibrarian.dev with subject line starting `[PQF-IMPL-SEC]`

I aim to acknowledge security reports within 72 hours.

## What counts as a security concern at this stage

Because PQF is pre-implementation, "security concerns" at this stage are
primarily specification-level:

- Flaws in the hybrid KEM combiner (§2.4)
- Gaps in signature coverage (§6.2, §8.3)
- AEAD mode or AAD construction issues (§5.2)
- Timing or side-channel implications of the recipient-trial procedure (§6.3, §6.4)
- Fail-closed bypass paths (§8.4)
- Anything that would cause a conforming reader to accept a file a conforming
  writer should not have produced

General spec feedback (clarity, readability, editorial) is also welcome but
does not require the `[PQF-SEC]` prefix — plain Discussions or Issues are
fine for that.

## Scope of responsibility

Until v1.0.0 ships, the specification may change in response to review. This
includes breaking changes. Any files produced by pre-1.0.0 implementations
may not be readable by the final v1 release.

I will maintain a public record of all specification changes in the change
log within `spec/PQF-SPEC-v1.md`.

## Acknowledgments

Contributors who identify specification issues will be acknowledged in the
spec's acknowledgments section (with permission). If you prefer to remain
anonymous, that preference will be honored.