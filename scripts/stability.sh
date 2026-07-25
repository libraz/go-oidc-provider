#!/usr/bin/env bash
# Wrapper around tools/stabilitytool. The tool is a separate Go module under
# tools/stabilitytool/ so its go/ast tooling stays out of the main module's
# go.sum. We invoke it with `go run` from that directory and inject the
# repo-rooted scan root, module path, and report location.
#
# Modes:
#   scripts/stability.sh            print the derived report
#   scripts/stability.sh --write    regenerate api/experimental.txt
#   scripts/stability.sh --check    fail when the checked-in report drifts
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

SCAN_ROOT="$REPO_ROOT/op"
MODULE_PATH="github.com/libraz/go-oidc-provider/op"
REPORT="$REPO_ROOT/api/experimental.txt"

# The tool module is deliberately outside the shipping inventory, so it is
# also outside any workspace a release or CI run creates. Workspace mode
# would refuse to build a directory the workspace does not use.
export GOWORK=off

cd "$REPO_ROOT/tools/stabilitytool"

mode="${1:-}"
case "$mode" in
  --write)
    go run . -root "$SCAN_ROOT" -module "$MODULE_PATH" -write "$REPORT"
    echo "wrote $REPORT"
    ;;
  --check)
    go run . -root "$SCAN_ROOT" -module "$MODULE_PATH" -check "$REPORT"
    ;;
  "")
    go run . -root "$SCAN_ROOT" -module "$MODULE_PATH"
    ;;
  *)
    echo "usage: stability.sh [--write|--check]" >&2
    exit 2
    ;;
esac
