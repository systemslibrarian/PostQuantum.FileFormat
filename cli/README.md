# `pqf` CLI

`pqf` is the command-line wrapper over the `PostQuantum.FileFormat` library.

## Commands

- `pqf keygen --type encrypt --public-out recipient.pub.pem --private-out recipient.identity.json`
- `pqf keygen --type sign --public-out signer.pub.pem --private-out signer.identity.json`
- `pqf encrypt --in plain.bin --out file.pqf --recipient recipient.pub.pem [--recipient recipient2.pub.pem] [--signing-key signer.identity.json] [--chunk-size 65536]`
- `pqf decrypt --in file.pqf --out plain.out.bin --identity recipient.identity.json [--mode authenticated|streaming]`
- `pqf inspect --in file.pqf [--json]`
- `pqf fingerprint --public-key recipient.pub.pem`

## Key file formats

- Public keys are armored PEM files using labels from spec §7:
	- `PQF PUBLIC KEY`
	- `PQF SIGNING PUBLIC KEY`
- Private identities are JSON files written by `pqf keygen` and consumed by
	`pqf encrypt` / `pqf decrypt`.

## Exit codes

- `0`: success
- `2`: usage error
- `3`: I/O or permissions error
- `4`: key parse/format error
- `5`: cryptographic refusal (`PqfRefusalReason`)
- `10`: internal error

In streaming mode, post-hoc signature/footer failures return exit code `5` and
are reported on stderr with `post-hoc-auth=true`.
