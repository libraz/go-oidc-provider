#!/usr/bin/env bash
# Run golangci-lint v2 against the repository.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

cd "$REPO_ROOT"

LINT="$(tool golangci-lint)"

log "$($LINT version 2>/dev/null || true)"
log "golangci-lint run ./..."
"$LINT" run ./...
