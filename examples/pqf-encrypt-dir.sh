#!/usr/bin/env bash
#
# examples/pqf-encrypt-dir.sh
#
# Encrypt a whole directory tree to a single .pqf file by piping a
# deterministically-ordered tar archive into `pqf encrypt`. Optional
# hybrid signature if --signing-key is provided.
#
# Usage:
#   pqf-encrypt-dir.sh <src-dir> <out.pqf> <recipient-pub.pem> [--signing-key <signer.key.json>]
#
# Requirements:
#   - GNU tar (for --sort=name, --mtime).
#   - pqf CLI on $PATH (install with `dotnet tool install --global PostQuantum.FileFormat.Cli --prerelease`).
#
# Notes:
#   - The tar layout is deterministic: same tree -> identical tar bytes.
#     PQF itself still introduces randomness (KEM ciphertexts, AEAD nonces),
#     so two encryptions of the same tree will produce different .pqf
#     bytes that decrypt to identical plaintext.

set -euo pipefail

if [[ $# -lt 3 ]]; then
    cat >&2 <<'EOF'
usage: pqf-encrypt-dir.sh <src-dir> <out.pqf> <recipient-pub.pem> [--signing-key <signer.key.json>]
EOF
    exit 2
fi

SRC_DIR="$1"; shift
OUT_PQF="$1"; shift
RECIPIENT="$1"; shift

SIGN_ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --signing-key)
            SIGN_ARGS+=(--signing-key "$2")
            shift 2
            ;;
        *)
            echo "unknown flag: $1" >&2
            exit 2
            ;;
    esac
done

if [[ ! -d "${SRC_DIR}" ]]; then
    echo "not a directory: ${SRC_DIR}" >&2
    exit 1
fi

# Deterministic tar: stable file order, zero owner/group, fixed mtime.
TMP_TAR="$(mktemp -t pqf-encrypt-dir-XXXXXX.tar)"
trap 'rm -f "${TMP_TAR}"' EXIT

tar \
    --sort=name \
    --owner=0 --group=0 --numeric-owner \
    --mtime='1970-01-01 00:00:00 UTC' \
    -C "$(dirname "${SRC_DIR}")" \
    -cf "${TMP_TAR}" \
    "$(basename "${SRC_DIR}")"

pqf encrypt \
    --in "${TMP_TAR}" \
    --out "${OUT_PQF}" \
    --recipient "${RECIPIENT}" \
    "${SIGN_ARGS[@]}"

echo "wrote ${OUT_PQF}"
