#!/usr/bin/env bash
# Create the repository's multi-module workspace.
#
# A release commit pins the storage-adapter manifests to the root tag that this
# very commit will create, so the tag does not exist while the commit is being
# verified. The workspace makes every pre-tag check resolve the root module from
# the checkout instead of the proxy, without shipping a `replace` to external
# adapter consumers. The file is gitignored: consumers never receive it.
#
# The member list is DERIVED, not written down twice. It is exactly the set of
# modules that scripts/verify.sh and scripts/test.sh run in workspace mode —
# the untagged entries of the shared inventory in lib.sh. Every other module
# (examples, sample, tools) is run with GOWORK=off against its own development
# `replace`, so adding one must not silently change what the workspace covers.
# Deriving the list is what keeps CI, `make verify`, and the release script from
# drifting apart: a workspace missing a module fails only inside that module,
# which is easy to mistake for a defect in the module itself.
#
#   scripts/workspace.sh            (re)create go.work
#   scripts/workspace.sh --members  print the member directories, one per line
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

cd "$REPO_ROOT"

# workspace_modules echoes the inventory entries that carry no build tag, as
# paths relative to the repository root so the generated go.work is readable
# and identical to the one CI produces.
workspace_modules() {
  while IFS=$'\t' read -r mod tags; do
    [ -n "$tags" ] && continue
    local rel="${mod#"$REPO_ROOT"}"
    rel="${rel#/}"
    printf '%s\n' "${rel:-.}"
  done < <(public_modules)
}

mapfile -t members < <(workspace_modules)
[ "${#members[@]}" -gt 0 ] || die "no workspace modules found; is this the repository root?"

case "${1:-}" in
  --members)
    printf '%s\n' "${members[@]}"
    ;;
  "")
    # go work init refuses to overwrite, and a stale file is exactly the
    # failure this script exists to prevent, so replace it outright.
    rm -f go.work
    go work init "${members[@]}"
    log "wrote go.work with ${#members[@]} modules"
    ;;
  *)
    die "usage: workspace.sh [--members]"
    ;;
esac
