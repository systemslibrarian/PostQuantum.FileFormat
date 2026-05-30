#!/usr/bin/env bash
#
# scripts/fetch-nist-kat.sh
#
# Download NIST KAT vector files for ML-KEM-768 (FIPS 203) and
# ML-DSA-87 (FIPS 204) into test-vectors/nist-kat/.
#
# The exact URL of each authoritative artifact moves periodically;
# update the constants below when NIST republishes. The harness in
# tests/PostQuantum.FileFormat.Kat consumes the resulting .rsp files.
#
# This script does NOT vendor the files into the repo — it materializes
# them into a gitignored directory for the local KAT run.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="${REPO_ROOT}/test-vectors/nist-kat"
mkdir -p "${TARGET_DIR}"

# TODO: Pin to specific NIST-published URLs once a stable mirror is
# selected. Until then, this script intentionally fails fast and tells
# the operator where to drop the files.
cat <<'EOF' >&2
fetch-nist-kat: this script is a placeholder.

To run the KAT harness, place the following files in:
    test-vectors/nist-kat/

  - ml-kem-768.rsp   (NIST FIPS 203 KAT response file)
  - ml-dsa-87.rsp     (NIST FIPS 204 KAT response file)

Once these files are present, run:

    dotnet run --project tests/PostQuantum.FileFormat.Kat

EOF
exit 1
