#!/usr/bin/env bash
# Assert every op.<Symbol> a shipped demo names in a comment is a symbol
# package op actually exports.
#
# The compiler checks the identifiers in code and says nothing about the
# ones in prose, so a comment can point an operator at a constructor that
# was planned and never written — and the reader has no way to tell that
# from a symbol they simply cannot find. Planned capability is describable
# without a name; an identifier in a comment is a promise the package
# keeps.
#
# Scope is the demo surface an embedder copies from: examples/ and cmd/.
# The library's own tree is not covered here.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

cd "$REPO_ROOT"

# The exported surface, read off the package itself rather than a
# hand-kept list. `go doc -all` prints grouped const / var declarations
# in full, which the package index form abbreviates with "..." — an
# abbreviated index would report every member but the first as missing.
symbols="$(GOWORK=off go doc -all ./op | awk '
  /^(const|var) \(/ { block = 1; next }
  block && /^\)/     { block = 0; next }
  block && match($0, /^\t[A-Za-z_][A-Za-z0-9_]*/) {
    print substr($0, RSTART + 1, RLENGTH - 1); next
  }
  match($0, /^[[:space:]]*(func|type|const|var)[[:space:]]+/) {
    rest = substr($0, RSTART + RLENGTH)
    if (match(rest, /^[A-Za-z_][A-Za-z0-9_]*/)) print substr(rest, 1, RLENGTH)
  }
' | sort -u)"

# An empty set would clear every reference at once, so a `go doc` that
# failed or a package that moved is a broken gate rather than a clean
# tree.
if [ "$(printf '%s\n' "$symbols" | grep -c .)" -lt 50 ]; then
  die "package op resolved to $(printf '%s\n' "$symbols" | grep -c .) exported symbols: the scan is broken, not the tree"
fi

mapfile -t files < <(git ls-files -- 'examples/*.go' 'cmd/*.go')
if [ "${#files[@]}" -eq 0 ]; then
  die "no tracked demo Go files matched: the scan is broken, not the tree"
fi

# Comment text only — everything from the first "//" on. A trailing "*"
# marks prose about a family ("the op.AuditDCR* constants"), which names
# no single symbol and is not a promise about one.
referenced="$(grep -hoE '//.*' "${files[@]}" |
  grep -oE '\bop\.[A-Z][A-Za-z0-9_]*\*?' |
  grep -v '\*$' |
  sed 's/^op\.//' | sort -u || true)"

bad="$(comm -23 <(printf '%s\n' "$referenced" | grep -v '^$' || true) <(printf '%s\n' "$symbols"))"

if [ -n "$bad" ]; then
  warn "demo comments name op symbols the package does not export:"
  while IFS= read -r name; do
    [ -z "$name" ] && continue
    printf '  - op.%s\n' "$name" >&2
    grep -nE "//.*\bop\.$name\b" "${files[@]}" >&2 || true
  done <<< "$bad"
  die "name a symbol that exists, or describe the capability without naming one"
fi
log "demo op symbol references OK ($(printf '%s\n' "$referenced" | grep -c .) named, $(printf '%s\n' "$symbols" | grep -c .) exported)"
