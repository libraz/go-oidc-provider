#!/usr/bin/env bash
# Wrapper around tools/stabilitytool. The tool is a separate Go module under
# tools/stabilitytool/ so its go/ast tooling stays out of the main module's
# go.sum. We invoke it with `go run` from that directory and inject the
# repo-rooted scan root, module path, and report locations.
#
# Two reports, always handled together so neither can be left behind:
#   api/experimental.txt  symbols exempt from the SemVer promise
#   api/stability.txt     symbols that name the release their contract froze in
#
# The write modes regenerate api/stability.txt first. It is the report that
# carries the history invariants, so a godoc that rewrites a released
# "Stable since" is rejected before either file on disk is touched.
#
# Modes:
#   scripts/stability.sh                  print both derived reports
#   scripts/stability.sh --write          regenerate both reports
#   scripts/stability.sh --check          fail when either checked-in report drifts
#   scripts/stability.sh --write-backfill regenerate, admitting a "Stable since"
#                                         marker newly added to a symbol that
#                                         genuinely shipped unmarked in that
#                                         release. It never admits a change to a
#                                         version already recorded — that would
#                                         rewrite what an existing release said.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

SCAN_ROOT="$REPO_ROOT/op"
MODULE_PATH="github.com/libraz/go-oidc-provider/op"
EXPERIMENTAL_REPORT="$REPO_ROOT/api/experimental.txt"
STABLE_REPORT="$REPO_ROOT/api/stability.txt"

# The tool module is deliberately outside the shipping inventory, so it is
# also outside any workspace a release or CI run creates. Workspace mode
# would refuse to build a directory the workspace does not use.
export GOWORK=off

cd "$REPO_ROOT/tools/stabilitytool"

stabilitytool() {
  go run . -root "$SCAN_ROOT" -module "$MODULE_PATH" "$@"
}

mode="${1:-}"
case "$mode" in
  --write)
    stabilitytool -kind stable -write "$STABLE_REPORT"
    echo "wrote $STABLE_REPORT"
    stabilitytool -kind experimental -write "$EXPERIMENTAL_REPORT"
    echo "wrote $EXPERIMENTAL_REPORT"
    ;;
  --write-backfill)
    stabilitytool -kind stable -write "$STABLE_REPORT" -allow-backfill
    echo "wrote $STABLE_REPORT (backfill allowed)"
    stabilitytool -kind experimental -write "$EXPERIMENTAL_REPORT"
    echo "wrote $EXPERIMENTAL_REPORT"
    ;;
  --check)
    stabilitytool -kind experimental -check "$EXPERIMENTAL_REPORT"
    stabilitytool -kind stable -check "$STABLE_REPORT"
    ;;
  "")
    echo "# ${EXPERIMENTAL_REPORT#"$REPO_ROOT/"}"
    stabilitytool -kind experimental
    echo "# ${STABLE_REPORT#"$REPO_ROOT/"}"
    stabilitytool -kind stable
    ;;
  *)
    echo "usage: stability.sh [--write|--write-backfill|--check]" >&2
    exit 2
    ;;
esac
