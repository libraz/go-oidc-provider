#!/usr/bin/env bash
# Run golangci-lint v2 against the repository.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

cd "$REPO_ROOT"

LINT="$(tool golangci-lint)"
lint_parallel="${GOLANGCI_LINT_CONCURRENCY:-$(go_test_parallelism)}"
case "$lint_parallel" in
  '' | *[!0-9]*) die "GOLANGCI_LINT_CONCURRENCY must be a positive integer (got: $lint_parallel)" ;;
esac
if [ "$lint_parallel" -lt 1 ]; then
  die "GOLANGCI_LINT_CONCURRENCY must be a positive integer (got: $lint_parallel)"
fi
go_max_procs="${GOMAXPROCS:-$lint_parallel}"
log "lint parallelism: workers=$lint_parallel, GOMAXPROCS=$go_max_procs (override GOLANGCI_LINT_CONCURRENCY or GOMAXPROCS)"

log "$($LINT version 2>/dev/null || true)"
while IFS=$'\t' read -r mod pkgs tags; do
  if [ -n "$tags" ]; then
    log "golangci-lint run --build-tags=$tags $pkgs ($mod)"
    (cd "$mod" && GOWORK=off GOMAXPROCS="$go_max_procs" "$LINT" run --concurrency "$lint_parallel" "--build-tags=$tags" "$pkgs")
  else
    log "golangci-lint run $pkgs ($mod)"
    (cd "$mod" && GOMAXPROCS="$go_max_procs" "$LINT" run --concurrency "$lint_parallel" "$pkgs")
  fi
done < <(public_modules)

# The build tools behind the repository's own gates. --config is explicit
# because golangci-lint resolves a relative config against the directory
# it runs in, and these modules sit two levels below the one that holds it.
while IFS=$'\t' read -r mod pkgs; do
  log "golangci-lint run $pkgs ($mod)"
  (cd "$mod" && GOWORK=off GOMAXPROCS="$go_max_procs" "$LINT" run --concurrency "$lint_parallel" --config "$REPO_ROOT/.golangci.yml" "$pkgs")
done < <(tool_modules)
