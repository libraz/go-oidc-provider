#!/usr/bin/env bash
# Assert the hot/cold examples route the Kinds their comments say they do.
#
# Example 08 tells the reader that moving from its inmem stand-in to the
# real Redis adapter of example 09 leaves its composite.With(...) calls
# unchanged, and that 09 additionally routes Sessions to the volatile
# backend because it accepts losing logins on a cache flush. An embedder
# copies 08 as the skeleton and trusts that sentence, so a drift between
# the two wirings has to fail here rather than ship as a silently wrong
# claim about which layer is durable.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

cd "$REPO_ROOT"

hot="examples/08-composite-hot-cold/main.go"
cold="examples/09-redis-volatile/main.go"

# The Kinds each example overrides onto its volatile backend. The
# variable name is part of the pattern: the default backend is wired
# through composite.WithDefault, so a With() call naming anything else
# is not a volatile routing decision.
volatile_kinds() {
  grep -oE 'composite\.With\(composite\.[A-Za-z0-9_]+, volatile\)' "$1" |
    sed -E 's/.*composite\.([A-Za-z0-9_]+), volatile\)/\1/' | sort -u
}

hot_kinds="$(volatile_kinds "$hot")"
cold_kinds="$(volatile_kinds "$cold")"

if [ -z "$hot_kinds" ] || [ -z "$cold_kinds" ]; then
  die "no volatile composite.With(...) calls found in $hot or $cold: the scan is broken, not the tree"
fi

if grep -qx 'Sessions' <<< "$hot_kinds"; then
  die "$hot routes Sessions to its volatile backend; its header doc says it keeps Sessions durable"
fi

expected="$(printf '%s\nSessions\n' "$hot_kinds" | sort -u)"
if [ "$cold_kinds" != "$expected" ]; then
  warn "the hot/cold examples no longer differ by Sessions alone:"
  printf '  %s: %s\n' "$hot" "$(tr '\n' ' ' <<< "$hot_kinds")" >&2
  printf '  %s: %s\n' "$cold" "$(tr '\n' ' ' <<< "$cold_kinds")" >&2
  die "update the wiring, or the comments in $hot that describe the difference"
fi
log "example store parity OK ($(printf '%s\n' "$hot_kinds" | wc -l | tr -d ' ') volatile Kinds shared, Sessions added by 09)"
