#!/usr/bin/env bash
# Run unit + integration tests. Flags:
#   --race    enable race detector
#   --cover   produce coverage profile (cover.out)
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

cd "$REPO_ROOT"

# The timeout is a hang detector, not a budget for legitimate work. The
# Argon2id packages (internal/authn/recovery, op/recoverykit) derive at
# production parameters on purpose — 64 MiB memory-hard, and the recovery
# verifier deliberately scans without an early exit — so they are the
# slowest packages in the tree by a wide margin. Under -race they land
# within a small factor of a 5m ceiling and then pass or fail depending on
# what else the machine is doing, which is not a gate. Raising the ceiling
# only when the detector is on keeps the fast path tight and still catches
# a deadlock long before a human would wait it out.
timeout=5m
cover_args=()
race=()

for arg in "$@"; do
  case "$arg" in
    --race)  race=( -race ); timeout=15m ;;
    --cover) cover_args=( -coverprofile=cover.out -covermode=atomic ) ;;
    *)       die "unknown flag: $arg" ;;
  esac
done

flags=( -count=1 "-timeout=$timeout" "${race[@]}" )

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
