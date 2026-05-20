#!/usr/bin/env bash
#
# examples/pqf-decrypt-dir.sh
#
# Decrypt a .pqf produced by pqf-encrypt-dir.sh and restore the tree.
# Uses Authenticated Mode by default so the file signature (when present)
# and footer are verified before any byte is written to disk.
#
# Usage:
#   pqf-decrypt-dir.sh <in.pqf> <dest-parent-dir> <identity.key.json>
#
# `dest-parent-dir` is the directory under which the original tree will
# be restored — the inner directory name comes from the tar archive.

set -euo pipefail

if [[ $# -ne 3 ]]; then
    cat >&2 <<'EOF'
usage: pqf-decrypt-dir.sh <in.pqf> <dest-parent-dir> <identity.key.json>
EOF
    exit 2
fi

IN_PQF="$1"
DEST_DIR="$2"
IDENTITY="$3"

mkdir -p "${DEST_DIR}"

TMP_TAR="$(mktemp -t pqf-decrypt-dir-XXXXXX.tar)"
trap 'rm -f "${TMP_TAR}"' EXIT

pqf decrypt \
    --in "${IN_PQF}" \
    --out "${TMP_TAR}" \
    --identity "${IDENTITY}" \
    --mode authenticated

tar -C "${DEST_DIR}" -xf "${TMP_TAR}"
echo "restored to ${DEST_DIR}"
