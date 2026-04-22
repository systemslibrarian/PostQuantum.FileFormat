#!/usr/bin/env bash
#
# scripts/smoke.sh
#
# End-to-end roundtrip smoke test for the in-tree pqf CLI.
#
# Generates two keypairs (encryption + signing), encrypts a sample plaintext,
# inspects the container, decrypts in Authenticated Mode, and verifies the
# decrypted output is byte-identical to the input. Also exercises a refusal
# path (truncated container must be rejected).
#
# Intended for:
#   - Contributors validating local changes before opening a PR.
#   - CI, as a black-box check that the assembled CLI works end-to-end.
#
# This script does NOT install anything globally. It runs the CLI from source
# via `dotnet run` against the project in cli/PostQuantum.FileFormat.Cli.
#
# Exit codes:
#   0  success
#   1  unexpected failure (build, encrypt, decrypt, diff, or refusal not raised)
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLI_PROJECT="${REPO_ROOT}/cli/PostQuantum.FileFormat.Cli/PostQuantum.FileFormat.Cli.csproj"
WORK_DIR="$(mktemp -d -t pqf-smoke-XXXXXX)"
CONFIG="${PQF_SMOKE_CONFIG:-Release}"

cleanup() {
    rm -rf "${WORK_DIR}"
}
trap cleanup EXIT

pqf() {
    dotnet run --project "${CLI_PROJECT}" -c "${CONFIG}" --no-restore --no-build -- "$@"
}

echo "==> Smoke test working directory: ${WORK_DIR}"
echo "==> Building CLI in ${CONFIG} configuration"
dotnet build "${CLI_PROJECT}" -c "${CONFIG}" --nologo -v minimal

cd "${WORK_DIR}"

echo "==> 1/7 Generate encryption keypair"
pqf keygen --type encrypt \
    --public-out  alice.pub.pem \
    --private-out alice.key.json

echo "==> 2/7 Generate signing keypair"
pqf keygen --type sign \
    --public-out  signer.pub.pem \
    --private-out signer.key.json

echo "==> 3/7 Create sample plaintext"
# Use a non-trivial size so chunk boundaries are exercised.
head -c 200000 /dev/urandom > sample.bin
SHA_IN="$(sha256sum sample.bin | awk '{print $1}')"
echo "    sample.bin sha256=${SHA_IN}"

echo "==> 4/7 Encrypt and sign"
pqf encrypt \
    --in sample.bin \
    --out sample.pqf \
    --recipient   alice.pub.pem \
    --signing-key signer.key.json

echo "==> 5/7 Inspect container (no plaintext released)"
pqf inspect --in sample.pqf > inspect.txt
head -n 20 inspect.txt

echo "==> 6/7 Decrypt in Authenticated Mode"
pqf decrypt \
    --in sample.pqf \
    --out sample.out.bin \
    --identity alice.key.json \
    --mode authenticated
SHA_OUT="$(sha256sum sample.out.bin | awk '{print $1}')"
echo "    sample.out.bin sha256=${SHA_OUT}"

if [[ "${SHA_IN}" != "${SHA_OUT}" ]]; then
    echo "FAIL: roundtrip hash mismatch (${SHA_IN} != ${SHA_OUT})" >&2
    exit 1
fi
echo "    OK: roundtrip hash matches"

echo "==> 7/7 Refusal path: truncated container must be rejected"
# Drop the last 32 bytes (definitely inside the footer / signature region).
SIZE="$(stat -c '%s' sample.pqf 2>/dev/null || stat -f '%z' sample.pqf)"
TRUNC_SIZE=$(( SIZE - 32 ))
head -c "${TRUNC_SIZE}" sample.pqf > sample.truncated.pqf

set +e
pqf decrypt \
    --in sample.truncated.pqf \
    --out should-not-exist.bin \
    --identity alice.key.json \
    --mode authenticated > truncated.stdout 2> truncated.stderr
RC=$?
set -e

if [[ ${RC} -eq 0 ]]; then
    echo "FAIL: truncated container was accepted (exit code 0)" >&2
    echo "----- stdout -----" >&2
    cat truncated.stdout >&2
    echo "----- stderr -----" >&2
    cat truncated.stderr >&2
    exit 1
fi
if [[ -s should-not-exist.bin ]]; then
    echo "FAIL: truncated container produced non-empty plaintext output" >&2
    exit 1
fi
echo "    OK: truncated container refused with exit code ${RC}"

echo
echo "PQF smoke test PASSED."
