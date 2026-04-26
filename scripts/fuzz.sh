#!/usr/bin/env bash
# Run all Fuzz* targets for the requested duration (default 30s).
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

cd "$REPO_ROOT"

duration="${1:-30s}"

mapfile -t targets < <(
  go test -list 'Fuzz.*' ./... 2>/dev/null \
    | awk '/^Fuzz/ {print FILENAME ":" $0}' FILENAME=stdin \
    | sort -u
)

# go test -list prints to stdout; we need to associate each target with the
# package it belongs to. Use a second pass to discover packages with fuzz
# targets, then run each target individually for the requested duration.

mapfile -t pkgs < <(
  go list ./... | while read -r pkg; do
    if go test -list 'Fuzz.*' "$pkg" 2>/dev/null | grep -q '^Fuzz'; then
      printf '%s\n' "$pkg"
    fi
  done
)

if [ "${#pkgs[@]}" -eq 0 ]; then
  warn "no Fuzz targets found"
  exit 0
fi

for pkg in "${pkgs[@]}"; do
  mapfile -t fuzz_funcs < <(go test -list 'Fuzz.*' "$pkg" | grep '^Fuzz' || true)
  for fn in "${fuzz_funcs[@]}"; do
    log "fuzz $pkg.$fn for $duration"
    go test -run='^$' -fuzz="^${fn}\$" -fuzztime="$duration" "$pkg"
  done
done
