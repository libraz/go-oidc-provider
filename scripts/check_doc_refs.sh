#!/usr/bin/env bash
# Assert no shipped artifact cites an internal planning document.
#
# The design notes those citations point at are untracked, so a reader
# of the published tree cannot follow them, and nothing checks whether
# the cited section still says what the citing comment claims. Removing
# them once is not enough: the same references kept reappearing, and
# stripping the last batch turned up comments whose cited justification
# had itself expired.
#
# The replacement is not a different citation — it is stating the
# constraint in a sentence that stands on its own. Public specs stay
# citable: those are versioned, addressable, and outlive the tree.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

cd "$REPO_ROOT"

# Tracked files only: the planning tree itself is gitignored and may say
# whatever it likes. The charter and the agent definitions are exempt
# because pointing a maintainer at the design notes is their entire
# job — they are addressed to someone who has the working copy.
mapfile -t files < <(git ls-files -- '*.go' '*.md' '*.yaml' '*.yml' '*.js' '*.html' '*.sql' |
  grep -vE '^(CLAUDE\.md|\.claude/)')

# A path or label that only resolves inside the working copy.
paths='(docs|backup)/(plans|research|adr)|idm-checklist|\bplans?/[0-9]{3}-|\b[Pp]lan [0-9]{3}\b'

# A design-document section label ("§A.12.9.1", "§L.2"). Public specs
# use the same glyph, so the pattern is applied only to lines that name
# no spec: an RFC number, a W3C / OpenID document, or an ECMA / NIST
# reference is enough to clear the line.
sections='§[A-Z]\.[0-9]'
spec_bearing='RFC ?[0-9]{4}|WebAuthn|OpenID|OAuth|FAPI|ECMA|NIST|SP ?800|X\.509'

hits="$(grep -nE "$paths" "${files[@]}" || true)"
hits+=$'\n'"$(grep -nE "$sections" "${files[@]}" | grep -vE "$spec_bearing" || true)"
hits="$(printf '%s\n' "$hits" | grep -v '^$' || true)"

if [ -n "$hits" ]; then
  warn "shipped artifacts cite an internal planning document:"
  printf '%s\n' "$hits" >&2
  die "state the constraint itself, or cite a public spec"
fi

# A doc link into internal/ can never resolve: godoc wants a full import
# path, and even spelled in full the package is absent from pkg.go.dev.
# The bracket text renders verbatim, so the reader is shown a package
# name they cannot open and the doc still has not said what it meant.
# Only the published tree is checked — the same link inside internal/ is
# read by maintainers who do have the source.
mapfile -t published < <(git ls-files -- 'op/*.go' | grep -v '_test\.go$')
internal_links="$(grep -nE '\[[a-z0-9_.,/-]*internal/' "${published[@]}" || true)"
if [ -n "$internal_links" ]; then
  warn "godoc on the published surface links into internal/:"
  printf '%s\n' "$internal_links" >&2
  die "state the behaviour instead of naming the internal package"
fi

log "doc references OK ($(printf '%s\n' "${files[@]}" | wc -l | tr -d ' ') tracked files)"
