#!/usr/bin/env bash
# Run the real-engine store contract suites. Unlike ordinary tagged tests,
# this release gate treats an unavailable container runtime as a failure.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

# The storage adapters are independently published modules. On a release commit
# their manifests already require the root tag that commit will create, so no
# proxy can resolve it and a standalone `GOWORK=off` run fails with "unknown
# revision". Every suite below therefore runs inside a workspace that supplies
# the root module from the checkout, exactly as the other verify scripts do.
# Standalone resolvability is not what this gate proves anyway — the release
# script's external-consumer smoke does that, against the real published tag.
#
# The workspace is built in a temporary directory rather than at the repository
# root so running this gate never leaves a go.work behind that would silently
# change how a later command resolves modules.
workspace_dir="$(mktemp -d)"
trap 'rm -rf "$workspace_dir"' EXIT
mapfile -t members < <("$SCRIPT_DIR/workspace.sh" --members)
(
  cd "$workspace_dir"
  go work init "${members[@]/#/$REPO_ROOT/}"
)
export GOWORK="$workspace_dir/go.work"

run_contracts() {
  local module="$1"
  log "go test -tags=testcontainers ./... ($module; required containers)"
  (
    cd "$module"
    RELEASE_CONTRACT_REQUIRED=1 \
      go test -count=1 -timeout=15m -tags=testcontainers ./...
  )
}

run_contracts "$REPO_ROOT/op/storeadapter/sql"
run_contracts "$REPO_ROOT/op/storeadapter/redis"
run_contracts "$REPO_ROOT/op/storeadapter/dynamodb"

# The composite RFC 7592 HTTP E2E additionally imports the root module's
# internal endpoint, which the shared workspace above already provides.
log "go test -tags=compositee2e ./... ($REPO_ROOT/op/storeadapter/sql; composite RFC 7592 HTTP E2E)"
(
  cd "$REPO_ROOT/op/storeadapter/sql"
  go test -count=1 -timeout=5m -tags=compositee2e ./...
)
