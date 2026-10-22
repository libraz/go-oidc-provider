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
# endpoint settings, read from defaultEndpoints() so it cannot drift from
# op/endpoints.go. The discovery document lives under the issuer path,
# not the mount prefix, so it is not part of the set.
allowed=()
while IFS= read -r p; do
  allowed+=("/oidc$p")
done < <(awk '/^func defaultEndpoints\(\)/{in_fn=1; next} in_fn && /^}/{exit}
  in_fn && match($0, /"\/[^"]*"/) {
    v = substr($0, RSTART + 1, RLENGTH - 2)
    if (v !~ /^\/\.well-known\//) print v
  }' op/endpoints.go)
if [ "${#allowed[@]}" -eq 0 ]; then
  die "could not read the default endpoint paths from op/endpoints.go"
fi

# Build a regex that matches any /oidc/ path reference in the
# examples. We grep .go files (godoc + log strings) and filter out
# the allowed paths; any remaining match is a divergence between
# documented and actual endpoint shape.
matches="$(grep -RhoIE '/oidc/[a-zA-Z0-9_./-]+' examples/ | sort -u || true)"

# A documented path is accepted when it equals an allowed path or
# extends it at a segment boundary (/oidc/interaction/<id>). Matching
# on any following character instead would accept every path an
# allowed one is a prefix of, so /oidc/authorize would pass as an
# extension of /oidc/auth.
bad=()
while IFS= read -r m; do
  [ -z "$m" ] && continue
  ok=0
  for a in "${allowed[@]}"; do
    case "$m" in
      "$a"|"$a"/*) ok=1; break ;;
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
