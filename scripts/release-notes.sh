#!/usr/bin/env bash
#
# scripts/release-notes.sh
#
# Extract the CHANGELOG section for a given version. Used by the
# release workflow to populate GitHub release notes from the same
# source that humans read.
#
# Usage:
#   scripts/release-notes.sh                  # extracts [Unreleased]
#   scripts/release-notes.sh 0.4.0-preview.2  # extracts [0.4.0-preview.2]
#
# Exit codes:
#   0  printed a section
#   1  no matching section found
#   2  bad arguments

set -euo pipefail

VERSION="${1:-Unreleased}"
CHANGELOG="${CHANGELOG_PATH:-CHANGELOG.md}"

if [[ ! -f "$CHANGELOG" ]]; then
    echo "release-notes: CHANGELOG not found at $CHANGELOG" >&2
    exit 2
fi

# Match "## [VERSION]" — escape regex metachars in the version.
escaped="$(printf '%s' "$VERSION" | sed -e 's/[]\/$*.^[]/\\&/g')"

awk -v ver="$escaped" '
    BEGIN { inside = 0 }
    # The opening line of our section.
    /^## \[/ {
        if (inside) { exit }
        if (match($0, "^## \\[" ver "\\]")) { inside = 1; print; next }
    }
    inside { print }
' "$CHANGELOG" \
    | sed '/^$/N;/^\n$/D'   # collapse runs of blank lines

# awk above returns 0 even if no section matched. Verify by checking
# whether the first line referenced our version.
if ! awk -v ver="$escaped" '/^## \[/ && match($0, "^## \\[" ver "\\]") { found=1; exit } END { exit !found }' "$CHANGELOG"; then
    echo "release-notes: no section [$VERSION] in $CHANGELOG" >&2
    exit 1
fi
