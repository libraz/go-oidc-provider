#!/usr/bin/env bash
# Assert no two examples register the same client-secret literal
# across DISTINCT example files. Multiple clients within a single
# example may share a demo secret (the embedder rotates them as
# a unit); the cross-example case is the one that lets a forgotten
# string slip through when an embedder copy-pastes from several
# examples.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

cd "$REPO_ROOT"

# Emit "<example_dir>\t<secret>" lines, deduplicated per file so
# intra-file repetition does not register as duplicate. The example
# directory is the second path component (examples/<dir>/...).
pairs="$(grep -RnE 'Secret: *"[^"]+"' examples/ \
  | sed -E 's#^examples/([^/]+)/.*Secret: *"([^"]+)".*#\1\t\2#' \
  | sort -u)"

if [ -z "$pairs" ]; then
  log "no client secrets registered in examples (nothing to check)"
  exit 0
fi

# Now group by secret value; any value appearing in two or more
# distinct example directories is the failure case.
dups="$(printf '%s\n' "$pairs" | awk -F'\t' '{print $2"\t"$1}' | sort | awk -F'\t' '
{
  if ($1 == prev) {
    print prev"\t"prev_dir; print $1"\t"$2
  }
  prev = $1; prev_dir = $2
}' | sort -u)"

if [ -n "$dups" ]; then
  warn "client-secret literals shared across distinct examples:"
  printf '%s\n' "$dups" >&2
  die "rename the duplicate literals so each example carries a unique demo secret"
fi
log "example secret literals OK ($(printf '%s\n' "$pairs" | awk -F'\t' '{print $2}' | sort -u | wc -l | tr -d ' ') unique across $(printf '%s\n' "$pairs" | awk -F'\t' '{print $1}' | sort -u | wc -l | tr -d ' ') examples)"
