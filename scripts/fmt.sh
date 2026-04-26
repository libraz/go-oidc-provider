#!/usr/bin/env bash
# Format Go sources with gofumpt + goimports.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

cd "$REPO_ROOT"

GOFUMPT="$(tool gofumpt)"
GOIMPORTS="$(tool goimports)"

log "gofumpt -w ."
"$GOFUMPT" -w -extra .

log "goimports -w -local github.com/libraz/go-oidc-provider"
"$GOIMPORTS" -w -local github.com/libraz/go-oidc-provider .
