#!/usr/bin/env bash
# Run govulncheck against the module.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

cd "$REPO_ROOT"

VULN="$(tool govulncheck)"
log "govulncheck ./..."
"$VULN" ./...
