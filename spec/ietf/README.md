# IETF Internet-Draft (work in progress)

This directory contains the kramdown-rfc source for a planned Independent
Submission Internet-Draft of the PQF format. It exists to make the spec
reviewable through the IETF datatracker and the CFRG mailing list — not
because the format requires IETF blessing to be useful.

## Status

`draft-clark-pqf-00` is a skeleton. It is not yet submitted. The
authoritative wire format lives in `../PQF-SPEC-v1.md`; this draft will
follow the reference spec, not the other way around.

## Building

Requires [kramdown-rfc](https://github.com/cabo/kramdown-rfc) and
[xml2rfc](https://github.com/ietf-tools/xml2rfc):

```bash
gem install kramdown-rfc
pip install xml2rfc
kramdown-rfc draft-clark-pqf-00.md > draft-clark-pqf-00.xml
xml2rfc --text  draft-clark-pqf-00.xml
xml2rfc --html  draft-clark-pqf-00.xml
```

## Why bother?

A spec that's never seen public cryptographic review is hard for outsiders
to evaluate. Even a single round of CFRG-list feedback on the combiner
construction (§2.4 of `PQF-SPEC-v1.md`) is more valuable to potential
adopters than another month of feature work.
