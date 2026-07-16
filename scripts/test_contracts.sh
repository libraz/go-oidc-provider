#!/usr/bin/env bash
# Run the real-engine store contract suites. Unlike ordinary tagged tests,
# this release gate treats an unavailable container runtime as a failure.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

run_contracts() {
  local module="$1"
  log "go test -tags=testcontainers ./... ($module; required containers)"
  (
    cd "$module"
    GOWORK=off RELEASE_CONTRACT_REQUIRED=1 \
      go test -count=1 -timeout=15m -tags=testcontainers ./...
  )
}

run_contracts "$REPO_ROOT/op/storeadapter/sql"
run_contracts "$REPO_ROOT/op/storeadapter/redis"

# The SQL adapter is an independently published submodule, so its normal
# tests deliberately run with GOWORK=off. The composite RFC 7592 HTTP E2E
# additionally imports the root module's internal endpoint; execute that one
# test package in a disposable workspace rather than weakening standalone
# module verification above.
workspace_dir="$(mktemp -d)"
trap 'rm -rf "$workspace_dir"' EXIT
(
  cd "$workspace_dir"
  go work init "$REPO_ROOT" "$REPO_ROOT/op/storeadapter/sql"
)
log "go test -tags=compositee2e ./... ($REPO_ROOT/op/storeadapter/sql; composite RFC 7592 HTTP E2E)"
(
  cd "$REPO_ROOT/op/storeadapter/sql"
  GOWORK="$workspace_dir/go.work" \
    go test -count=1 -timeout=5m -tags=compositee2e ./...
)
