#!/usr/bin/env bash
# Run unit + integration tests. Flags:
#   --race    enable race detector
#   --cover   produce coverage profile (cover.out)
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

cd "$REPO_ROOT"

flags=( -count=1 -timeout=5m )
cover_args=()

for arg in "$@"; do
  case "$arg" in
    --race)  flags+=( -race ) ;;
    --cover) cover_args=( -coverprofile=cover.out -covermode=atomic ) ;;
    *)       die "unknown flag: $arg" ;;
  esac
done

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
    (cd "$mod" && GOWORK=off go test "${flags[@]}" "${entry_cover[@]}" "$args" "$pkgs")
  else
    log "go test ${flags[*]} ${entry_cover[*]} $pkgs ($mod)"
    (cd "$mod" && go test "${flags[@]}" "${entry_cover[@]}" "$pkgs")
  fi
done < <(public_modules)

if [ "${#cover_args[@]}" -gt 0 ]; then
  log "Coverage written to cover.out (HTML: 'go tool cover -html=cover.out')"
fi
