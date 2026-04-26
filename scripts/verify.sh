#!/usr/bin/env bash
# One-shot verification: format check, vet, lint, build, test.
# This is the script invoked locally before opening a PR.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

cd "$REPO_ROOT"

GOFUMPT="$(tool gofumpt)"
GOIMPORTS="$(tool goimports)"

log "gofumpt -l (no changes expected)"
fumpt_diff="$("$GOFUMPT" -l -extra .)"
if [ -n "$fumpt_diff" ]; then
  printf '%s\n' "$fumpt_diff" >&2
  die "gofumpt would reformat the files above; run 'make fmt'"
fi

log "goimports -l (no changes expected)"
imports_diff="$("$GOIMPORTS" -l -local github.com/libraz/go-oidc-provider .)"
if [ -n "$imports_diff" ]; then
  printf '%s\n' "$imports_diff" >&2
  die "goimports would reformat the files above; run 'make fmt'"
fi

log "go vet ./..."
go vet ./...

"$SCRIPT_DIR/lint.sh"

log "go build ./..."
go build ./...

"$SCRIPT_DIR/test.sh" --race

log "verify OK"
