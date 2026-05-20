# Phase Notes (Phase 1)

## Spec ambiguities and resolutions

- CBOR map key ordering in spec section 2.5 uses the phrase "byte-wise lexicographic order of their encoded form (length first, then lexicographic)".
  Resolution: implemented exactly as stated, comparing encoded key length first, then byte-wise lexicographic order.
- `CborValue.NegInt(long)` semantic wording in the build prompt says "value is the negated form, not the raw negative".
  Resolution: represented the canonical CBOR major type 1 integer argument directly (`n` where represented value is `-1 - n`), and rejected negative inputs to `NegInt`.

## Deterministic CBOR validation strategy

- Chosen approach: parse-strict custom deterministic parser (equivalent to option A parse-strict in spec section 2.5), rather than permissive parse plus re-encode compare.
- Rationale: enforce all required refusal conditions during parse (non-shortest integers, indefinite lengths, map ordering, duplicate keys, floats/simple values, trailing bytes).

## Deviations from spec

- None.

## Library/runtime notes

- Target framework: `net8.0`.
- BCL APIs used: `System.Formats.Cbor` was not required for the final deterministic parser implementation; Phase 1 foundation uses BCL only (no third-party dependency in main project).
- CI runtime: GitHub Actions workflow uses .NET 8 via `actions/setup-dotnet@v4`.
