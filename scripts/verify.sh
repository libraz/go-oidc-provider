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
  die "goimports would reformat the files above; run 'make format'"
fi

while IFS=$'\t' read -r mod pkgs tags; do
  args="$(go_args_for "$tags")"
  log "go vet $args $pkgs ($mod)"
  if [ -n "$args" ]; then
    (cd "$mod" && GOWORK=off go vet "$args" "$pkgs")
  else
    (cd "$mod" && go vet "$pkgs")
  fi
done < <(public_modules)

"$SCRIPT_DIR/lint.sh"

while IFS=$'\t' read -r mod pkgs tags; do
  args="$(go_args_for "$tags")"
  log "go build $args $pkgs ($mod)"
  if [ -n "$args" ]; then
    (cd "$mod" && GOWORK=off go build "$args" "$pkgs")
  else
    (cd "$mod" && go build "$pkgs")
  fi
done < <(public_modules)

"$SCRIPT_DIR/test.sh" --race

# The gates below are only worth as much as the tools behind them, and the
# tools live in modules the shipping inventory deliberately excludes, so
# their own tests would otherwise never run here.
for tool_mod in scenariotool stabilitytool; do
  if [ -f "$REPO_ROOT/tools/$tool_mod/go.mod" ]; then
    log "go test ./... (tools/$tool_mod)"
    (cd "$REPO_ROOT/tools/$tool_mod" && GOWORK=off go test ./...)
  fi
done

log "scenariotool validate"
"$SCRIPT_DIR/scenario.sh" validate

# Fails on every way a catalog row and its test can disagree: a row
# with no test, a test with no row, a test that runs under a row
# declared out-of-scope, a covered_by naming a test that no longer
# exists, and a row bound only to a skip stub. --strict is a superset
# of --check-bindings, so running both would only repeat the same
# `go test -list`; the tolerant mode stays available as
# `make scenario-coverage-bindings` for a tree mid-change.
log "scenariotool coverage --strict"
"$SCRIPT_DIR/scenario.sh" coverage --strict

log "scenariotool advisories --check"
"$SCRIPT_DIR/scenario.sh" advisories --check >/dev/null

log "stabilitytool --check"
"$SCRIPT_DIR/stability.sh" --check

"$SCRIPT_DIR/verify_examples.sh"

# Say what this run did NOT cover. verify_examples.sh compiles and vets the
# examples; nothing here boots one, so an example whose configuration op.New
# now rejects passes every gate above. `make verify-examples-harness` is that
# gate, and the release pre-flight requires it.
log "verify OK (examples compiled, not booted — run 'make verify-examples-harness' for the runtime gate)"
