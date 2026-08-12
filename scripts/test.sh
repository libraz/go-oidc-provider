#!/usr/bin/env bash
# Run unit + integration tests. Flags:
#   --race    enable race detector
#   --cover   produce coverage profile (cover.out)
#
# GO_TEST_PARALLEL limits both Go package work and t.Parallel scheduling. It
# defaults to 2 so the race suite does not monopolise a developer workstation;
# CI or a deliberately measured local run can override it.
# GO_TEST_TIMEOUT and GO_TEST_RACE_TIMEOUT override the per-package hang
# detector when a deliberately slower local profile needs a different limit.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

cd "$REPO_ROOT"

# The timeout is a hang detector, not a budget for legitimate work. The
# deliberately conservative default parallelism makes the large scenario
# suite and production-parameter Argon2id checks take materially longer than
# an unrestricted run, especially under -race. Keep a finite detector while
# leaving enough room for that intentional work; callers can tighten it with
# GO_TEST_TIMEOUT / GO_TEST_RACE_TIMEOUT when diagnosing a suspected hang.
timeout="${GO_TEST_TIMEOUT:-30m}"
cover_args=()
race=()
test_parallel="$(go_test_parallelism)"
go_max_procs="${GOMAXPROCS:-$test_parallel}"

for arg in "$@"; do
  case "$arg" in
    --race)  race=( -race ); timeout="${GO_TEST_RACE_TIMEOUT:-${GO_TEST_TIMEOUT:-45m}}" ;;
    --cover) cover_args=( -coverprofile=cover.out -covermode=atomic ) ;;
    *)       die "unknown flag: $arg" ;;
  esac
done

flags=( -count=1 "-timeout=$timeout" -p "$test_parallel" "-parallel=$test_parallel" "${race[@]}" )
log "test parallelism: packages/subtests=$test_parallel, GOMAXPROCS=$go_max_procs (override GO_TEST_PARALLEL or GOMAXPROCS)"

while IFS=$'\t' read -r mod pkgs tags; do
  # The example verification harnesses are in the inventory so they get vetted,
  # linted and built here, but their tests boot every example as a real process
  # (and need a browser) — too long for this suite. scripts/verify_example_harness.sh
  # runs them; the release pre-flight requires it.
  if is_verify_harness_module "$mod"; then
    log "skipping $mod tests (run 'make verify-examples-harness')"
    continue
  fi
  # A module can appear twice with different package patterns — the host
  # module is scanned once untagged and once narrowed to the build-tagged
  # examples subtree. The profile is named after the module directory, so
  # only the module-wide pass may write it; a narrowed pass would truncate
  # the profile the earlier one produced.
  entry_cover=()
  if [ "$pkgs" = "./..." ]; then
    entry_cover=( "${cover_args[@]}" )
  fi
  args="$(go_args_for "$tags")"
  if [ -n "$args" ]; then
    log "go test ${flags[*]} ${entry_cover[*]} $args $pkgs ($mod)"
    (cd "$mod" && GOWORK=off GOMAXPROCS="$go_max_procs" go test "${flags[@]}" "${entry_cover[@]}" "$args" "$pkgs")
  else
    log "go test ${flags[*]} ${entry_cover[*]} $pkgs ($mod)"
    (cd "$mod" && GOMAXPROCS="$go_max_procs" go test "${flags[@]}" "${entry_cover[@]}" "$pkgs")
  fi
done < <(public_modules)

if [ "${#cover_args[@]}" -gt 0 ]; then
  log "Coverage written to cover.out (HTML: 'go tool cover -html=cover.out')"
fi
