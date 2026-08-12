#!/usr/bin/env bash
# Run all Fuzz* targets for the requested duration (default 30s).
#
# Every module in the shipping inventory is scanned, not just the root: the
# storage adapters are separate modules, so a root-level `go list ./...` never
# sees them and their fuzz targets — the identifier validator that guards
# embedder-supplied table and schema names, for one — would never run.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

cd "$REPO_ROOT"

duration="${1:-30s}"
test_parallel="$(go_test_parallelism)"
go_max_procs="${GOMAXPROCS:-$test_parallel}"
log "fuzz parallelism: workers=$test_parallel, GOMAXPROCS=$go_max_procs (override GO_TEST_PARALLEL or GOMAXPROCS)"

# mod_go runs a go subcommand inside a module of the inventory, applying that
# module's build tags. Tagged modules (examples, harnesses, sample) resolve the
# root through their own development `replace` and so run with the workspace
# off; untagged ones run in workspace mode, exactly as verify.sh and test.sh do
# — a release commit pins the adapters to a tag that does not exist yet, and
# only the workspace makes them resolve against this checkout.
mod_go() {
  local mod="$1" tags="$2" sub="$3"
  shift 3
  if [ -n "$tags" ]; then
    (cd "$mod" && GOWORK=off GOMAXPROCS="$go_max_procs" go "$sub" "-tags=$tags" "$@")
  else
    (cd "$mod" && GOMAXPROCS="$go_max_procs" go "$sub" "$@")
  fi
}

# fuzz_targets emits "<package>\t<FuzzName>" for every fuzz target in a module.
# `go test -list` is asked per package because its output carries no package
# attribution when several packages are listed at once, and its result is read
# through a variable rather than piped into a matcher: `set -o pipefail` turns
# the SIGPIPE that an early-exiting `grep -q` sends the producer into a failed
# pipeline, which silently reads as "this package has no fuzz targets".
fuzz_targets() {
  local mod="$1" pkgs="$2" tags="$3" pkg listing fn
  while read -r pkg; do
    listing="$(mod_go "$mod" "$tags" test -list 'Fuzz.*' "$pkg" 2>/dev/null || true)"
    while read -r fn; do
      case "$fn" in
        Fuzz*) printf '%s\t%s\n' "$pkg" "$fn" ;;
      esac
    done <<<"$listing"
  done < <(mod_go "$mod" "$tags" list "$pkgs" 2>/dev/null || true)
}

total=0

while IFS=$'\t' read -r mod pkgs tags; do
  while IFS=$'\t' read -r pkg fn; do
    log "fuzz $pkg.$fn for $duration"
    mod_go "$mod" "$tags" test -p "$test_parallel" "-parallel=$test_parallel" -run='^$' -fuzz="^${fn}\$" -fuzztime="$duration" "$pkg" </dev/null
    total=$((total + 1))
  done < <(fuzz_targets "$mod" "$pkgs" "$tags")
done < <(public_modules)

if [ "$total" -eq 0 ]; then
  warn "no Fuzz targets found"
  exit 0
fi

log "ran $total fuzz target(s) for $duration each"
