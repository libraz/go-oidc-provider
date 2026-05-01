#!/usr/bin/env bash
# Wrapper around tools/scenariotool. The tool is a separate Go module
# under tools/scenariotool/, so its YAML dependency does not bleed
# into the main module's go.sum. We invoke it with `go run` from that
# directory and inject repo-rooted defaults for -dir / -tests.
#
# See test/scenarios/catalog/README.md for the catalog schema and
# ADR 0023 for the binding rules between catalog rows and Go test
# function names.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

CATALOG_DIR="$REPO_ROOT/test/scenarios/catalog"
TESTS_PATTERN="$REPO_ROOT/test/scenarios/..."

cd "$REPO_ROOT/tools/scenariotool"

if [ "$#" -eq 0 ] || [[ "$1" == "-h" || "$1" == "--help" || "$1" == "help" ]]; then
  exec go run . help
fi

cmd="$1"
shift

# Auto-inject -dir / -tests when the caller did not specify them.
inject_dir=1
inject_tests=1
for arg in "$@"; do
  case "$arg" in
    -dir|--dir|-dir=*|--dir=*) inject_dir=0 ;;
    -tests|--tests|-tests=*|--tests=*) inject_tests=0 ;;
  esac
done

extra=()
[ "$inject_dir" -eq 1 ] && extra+=( -dir "$CATALOG_DIR" )
case "$cmd" in
  coverage)
    extra+=( -cwd "$REPO_ROOT" )
    if [ "$inject_tests" -eq 1 ]; then
      extra+=( -tests "./test/scenarios/..." )
    fi
    ;;
  lookup|next|advisories)
    extra+=( -cwd "$REPO_ROOT" )
    ;;
esac

exec go run . "$cmd" "${extra[@]}" "$@"
