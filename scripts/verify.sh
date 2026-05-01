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

while IFS=$'\t' read -r mod tags; do
  args="$(go_args_for "$tags")"
  log "go vet $args ./... ($mod)"
  if [ -n "$args" ]; then
    (cd "$mod" && go vet "$args" ./...)
  else
    (cd "$mod" && go vet ./...)
  fi
done < <(public_modules)

"$SCRIPT_DIR/lint.sh"

while IFS=$'\t' read -r mod tags; do
  args="$(go_args_for "$tags")"
  log "go build $args ./... ($mod)"
  if [ -n "$args" ]; then
    (cd "$mod" && go build "$args" ./...)
  else
    (cd "$mod" && go build ./...)
  fi
done < <(public_modules)

"$SCRIPT_DIR/test.sh" --race

log "scenariotool advisories --check"
"$SCRIPT_DIR/scenario.sh" advisories --check >/dev/null

"$SCRIPT_DIR/verify_examples.sh"

log "verify OK"
