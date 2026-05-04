#!/usr/bin/env bash
# Assert every /oidc/* path documented in examples/ is in the closed
# set the OP actually mounts. The closed set is derived from the
# defaults op/endpoints.go publishes: any embedder-overridable path
# is excluded so a copy-pasted curl probe matches the library's
# out-of-the-box wire shape.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

cd "$REPO_ROOT"

# The closed set of /oidc/<path> values the OP serves with default
# endpoint settings. Update this list when op/endpoints.go grows a
# new default.
allowed=(
  "/oidc/auth"
  "/oidc/token"
  "/oidc/jwks"
  "/oidc/userinfo"
  "/oidc/par"
  "/oidc/revoke"
  "/oidc/introspect"
  "/oidc/end_session"
  "/oidc/register"
  "/oidc/backchannel-logout"
  "/oidc/bc-authorize"
  "/oidc/device_authorization"
  "/oidc/interaction"
)

# Build a regex that matches any /oidc/ path reference in the
# examples. We grep .go files (godoc + log strings) and filter out
# the allowed paths; any remaining match is a divergence between
# documented and actual endpoint shape.
matches="$(grep -RhoIE '/oidc/[a-zA-Z0-9_./-]+' examples/ | sort -u || true)"

bad=()
while IFS= read -r m; do
  [ -z "$m" ] && continue
  ok=0
  for a in "${allowed[@]}"; do
    case "$m" in
      "$a"|"$a"?*) ok=1; break ;;
    esac
  done
  if [ "$ok" = 0 ]; then
    bad+=("$m")
  fi
done <<< "$matches"

if [ "${#bad[@]}" -gt 0 ]; then
  warn "examples reference /oidc paths not in the closed set:"
  for b in "${bad[@]}"; do
    printf '  - %s\n' "$b" >&2
    grep -RnIF "$b" examples/ >&2 || true
  done
  die "fix the example godoc / log strings to match op/endpoints.go defaults"
fi
log "example endpoints OK (${#allowed[@]} allowed)"
