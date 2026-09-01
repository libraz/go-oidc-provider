#!/usr/bin/env bash
# Wrapper around tools/failopentool — the fail-open gate.
#
# The tool is a separate Go module under tools/failopentool/ so it can
# run while the main module is mid-edit; it parses sources rather than
# building them for the same reason.
#
# See the tool's package doc for the exact shape it reports and for what
# belongs in api/failopen.txt.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

# The tool module is deliberately outside the shipping inventory, so it
# is also outside any workspace a release or CI run creates.
export GOWORK=off

cd "$REPO_ROOT/tools/failopentool"

exec go run . -root "$REPO_ROOT" "$@"
