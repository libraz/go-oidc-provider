#!/usr/bin/env bash
# Assert the two development opt-ins stay honest in both directions.
#
# 1. No example carries an opt-in it does not need. A dead
#    WithAllowLocalhostLoopback() teaches by example that the option is
#    part of the boilerplate, which is the opposite of what the README
#    says ("add neither unless the validator has actually rejected your
#    wiring"). The option compiles and boots either way, so nothing but
#    a static check notices.
# 2. The counts the READMEs quote match the tree. The prose used to
#    claim every loopback-binding example reaches for both options; the
#    number has drifted twice since. A reader who believes an inflated
#    count copies a security-relevant option into a production stack.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

cd "$REPO_ROOT"

# Example directories are numbered; examples/internal/ holds shared
# helpers and verification harnesses, which are not tutorials.
total="$(find examples -maxdepth 1 -type d -name '[0-9]*' | wc -l | tr -d ' ')"

# users <option> — example directory names calling the option, one per line.
users() {
  grep -rl "op.$1()" examples --include='*.go' | cut -d/ -f2 | sort -u
}

# evidence <dir> <regex> — non-comment lines in the example matching the
# regex, i.e. wiring rather than a mention in prose. Comment lines are
# dropped because every one of these examples explains the option right
# above the call, so a prose-only match proves nothing.
evidence() {
  grep -rhE "$2" "examples/$1" --include='*.go' | grep -vE '^[[:space:]]*//' || true
}

loopback_users="$(users WithAllowLocalhostLoopback)"
bcl_users="$(users WithAllowInsecureBackchannelLogoutForDev)"

fail=0
for dir in $loopback_users; do
  if [ -z "$(evidence "$dir" 'localhost')" ]; then
    warn "examples/$dir calls WithAllowLocalhostLoopback but spells no host \"localhost\""
    fail=1
  fi
done
for dir in $bcl_users; do
  if [ -z "$(evidence "$dir" 'BackchannelLogoutURI.*http://')" ]; then
    warn "examples/$dir calls WithAllowInsecureBackchannelLogoutForDev but registers no plain-http backchannel_logout_uri"
    fail=1
  fi
done
[ "$fail" -eq 0 ] || die "drop the opt-in from the example, or wire what it exists to admit"

loopback_count="$(printf '%s\n' "$loopback_users" | grep -c . || true)"
bcl_count="$(printf '%s\n' "$bcl_users" | grep -c . || true)"

# claim <file> <option> <sed-body> — the count the README states for an
# option, normalised to "<count> <total>". The paragraph documenting each
# option begins with the option name in backticks, so the search starts
# there and reads the few lines that make up the sentence.
claim() {
  awk -v opt="$2" '
    index($0, "`" opt "`") == 1 { grab = 8 }
    grab > 0 { buf = buf $0 " "; if (--grab == 0) { print buf; exit } }
  ' "$1" | sed -nE "$3"
}

check_readme() {
  local file="$1" option="$2" want_count="$3" expr="$4" stated
  stated="$(claim "$file" "$option" "$expr")"
  [ -n "$stated" ] || die "$file: no example count stated for $option (expected \"$want_count of $total\")"
  [ "$stated" = "$want_count $total" ] ||
    die "$file: $option is stated as \"$stated\" but the tree has \"$want_count $total\""
}

# English states the count first ("9 of the 43 examples"), Japanese the
# total first ("43 例のうち 9 例"), so each language needs its own
# extraction and the Japanese one swaps the capture groups back.
#
# Both leading wildcards end on a non-digit: POSIX ERE has no lazy
# quantifier, so a bare `.*` swallows all but the last digit of a
# two-digit count and the check would compare "3" against "43".
en='s/.*[^0-9]([0-9]+) of the ([0-9]+) examples.*/\1 \2/p'
ja='s/.*[^0-9]([0-9]+) 例のうち ([0-9]+) 例.*/\2 \1/p'
check_readme README.md WithAllowLocalhostLoopback "$loopback_count" "$en"
check_readme README.md WithAllowInsecureBackchannelLogoutForDev "$bcl_count" "$en"
check_readme README_ja.md WithAllowLocalhostLoopback "$loopback_count" "$ja"
check_readme README_ja.md WithAllowInsecureBackchannelLogoutForDev "$bcl_count" "$ja"

log "example dev opt-ins OK ($loopback_count loopback, $bcl_count insecure-backchannel, of $total examples)"
