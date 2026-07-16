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

while IFS=$'\t' read -r mod tags; do
  args="$(go_args_for "$tags")"
  if [ -n "$args" ]; then
    log "go test ${flags[*]} ${cover_args[*]} $args ./... ($mod)"
    (cd "$mod" && GOWORK=off go test "${flags[@]}" "${cover_args[@]}" "$args" ./...)
  else
    log "go test ${flags[*]} ${cover_args[*]} ./... ($mod)"
    (cd "$mod" && go test "${flags[@]}" "${cover_args[@]}" ./...)
  fi
done < <(public_modules)

if [ "${#cover_args[@]}" -gt 0 ]; then
  log "Coverage written to cover.out (HTML: 'go tool cover -html=cover.out')"
fi
