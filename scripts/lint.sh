#!/usr/bin/env bash
# Run golangci-lint v2 against the repository.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

cd "$REPO_ROOT"

LINT="$(tool golangci-lint)"

log "$($LINT version 2>/dev/null || true)"
while IFS=$'\t' read -r mod pkgs tags; do
  if [ -n "$tags" ]; then
    log "golangci-lint run --build-tags=$tags $pkgs ($mod)"
    (cd "$mod" && GOWORK=off "$LINT" run "--build-tags=$tags" "$pkgs")
  else
    log "golangci-lint run $pkgs ($mod)"
    (cd "$mod" && "$LINT" run "$pkgs")
  fi
done < <(public_modules)
