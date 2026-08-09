#!/usr/bin/env bash
# Run the examples/ verification harnesses — the only gates that boot each
# example as a real process and call its op.New. `make verify-examples`
# merely compiles and vets the tree, so a configuration an example can no
# longer construct compiles green and fails only here.
#
#   verify_example_harness.sh api      # examples/internal/apiverify
#   verify_example_harness.sh browser  # examples/internal/browserverify
#   verify_example_harness.sh all      # both (default)
#
# Extra arguments are passed through to `go test` (e.g. `-run TestExample01`).
#
# Each harness is its own module and neither is a go.work member, so every run
# is `cd <module> && GOWORK=off` — a root-level `go test ./examples/...` fails
# with "directory prefix does not contain main module", and leaving the
# workspace on fails with "not listed in go.work" once a release commit has
# written one.
#
# browserverify skips when no Chrome/Chromium is installed so a developer
# without a browser still gets a green tree. Set BROWSERVERIFY_REQUIRED=1 to
# turn a missing browser — and a run that executed zero browser cases — into a
# failure; the release pre-flight does exactly that.
#
# EXAMPLE_HARNESS_TIMEOUT overrides the per-harness `go test -timeout` (the go
# default of 10m is not enough: each case builds and boots an example, and
# browserverify budgets up to 90s of browser work per case).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

cd "$REPO_ROOT"

timeout="${EXAMPLE_HARNESS_TIMEOUT:-45m}"

mode="all"
if [ "$#" -gt 0 ]; then
  case "$1" in
    api | browser | all)
      mode="$1"
      shift
      ;;
  esac
fi

run_harness() {
  local dir="$1" tag="$2"
  shift 2
  [ -f "$dir/go.mod" ] || die "harness module not found: $dir/go.mod"
  log "go test -tags $tag ./... ($dir)"
  (cd "$dir" && GOWORK=off go test -count=1 -timeout="$timeout" -tags "$tag" "$@" ./...)
}

api_dir="$REPO_ROOT/examples/internal/apiverify"
browser_dir="$REPO_ROOT/examples/internal/browserverify"

case "$mode" in
  api)
    run_harness "$api_dir" apiverify "$@"
    ;;
  browser)
    run_harness "$browser_dir" browserverify "$@"
    ;;
  all)
    run_harness "$api_dir" apiverify "$@"
    run_harness "$browser_dir" browserverify "$@"
    ;;
  *)
    die "usage: verify_example_harness.sh [api|browser|all] [go test args...]"
    ;;
esac

log "example harness OK ($mode)"
