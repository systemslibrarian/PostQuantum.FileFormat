# Maintainers

A single source of truth for who owns this project, how to reach them,
and what the response-time expectations are.

## Project lead

**Paul Clark** — `systemslibrarian@gmail.com`

- GitHub: [@systemslibrarian](https://github.com/systemslibrarian)
- Time zone: US Eastern (UTC-5 / UTC-4)

## Areas of ownership

| Area | Owner |
|---|---|
| Specification (`spec/`) | Paul Clark |
| .NET reference implementation (`src/`, `cli/`) | Paul Clark |
| Test vectors (`tests/PostQuantum.FileFormat.TestVectors/`, `test-vectors/`) | Paul Clark |
| Rust reader (`impl/rust/pqf-reader/`) | Paul Clark |
| Rust writer (`impl/rust/pqf-writer/`) | Paul Clark |
| Python binding (`bindings/python/`) | Paul Clark |
| WASM binding (`bindings/wasm/`) | Paul Clark |
| CI / supply-chain (`.github/`, `Directory.Build.props`) | Paul Clark |
| Symbolic model (`spec/symbolic/`) | **Contributors wanted** — see [`spec/symbolic/README.md`](./spec/symbolic/README.md) |

The "Contributors wanted" rows are paths where outside expertise has
the most leverage. A serious PR on those will be reviewed promptly.

## Response-time expectations

These are commitments. If a response is overdue, ping again or escalate
via the channels below — none of these are SLAs in the contractual
sense, but the project takes the times seriously.

| Channel | Target first response |
|---|---|
| [Security advisory](https://github.com/systemslibrarian/PostQuantum.FileFormat/security/advisories/new) | **48 hours** for acknowledgment; triage within 5 business days. |
| Bug report (public issue) | 5 business days. |
| Spec review issue | 7 business days. |
| Pull request (non-trivial) | 10 business days. |
| Refusal-case issue | 7 business days; reproducible cases get folded into the negative vectors. |
| Discussion thread | Best effort; no SLA. |

## Coordinated disclosure

PQF uses GitHub's private security advisory channel. The disclosure
process:

1. Reporter submits a private security advisory with a reproducer.
2. Maintainer acknowledges within 48 hours.
3. Maintainer triages and assigns a CVSS score; agrees an embargo
   window with the reporter (default **90 days**).
4. Fix is developed in a private fork attached to the advisory.
5. Coordinated release: advisory publishes, fix lands on `main`, NuGet
   tag is cut, CVE is requested if applicable.

The default 90-day window is negotiable downward when the fix is
trivial and the exposure is high, or upward when the fix is risky
and the exposure is low. **No silent fixes.** Every security-driven
commit on `main` will reference its advisory once embargoed.

## Becoming a maintainer

There is no formal application. Maintainership is invited based on
demonstrated contribution and judgment over time. Things that
contribute toward an invitation:

- Sustained PR contributions that pass review without major rework.
- Review participation on PRs by others, especially spec review.
- Carrying out a non-trivial scoped deliverable (e.g. completing the
  Rust writer or shipping the Python binding to PyPI).

## Bus factor

The project is currently single-maintainer. That is a bus-factor
problem and it is acknowledged. If you have used PQF and want to
help reduce it, see "Becoming a maintainer" above.
