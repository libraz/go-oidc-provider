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

# Every tracked file, not a list of extensions. A maintained list of
# suffixes is a second table that has to be remembered whenever a file
# type enters the tree, and it silently exempts whatever nobody thought
# to add: a dead citation lived in a tracked .json for as long as the
# list named only source and markup. Binary content is skipped by grep
# -I below rather than by guessing at suffixes.
#
# The planning tree itself is gitignored and may say whatever it likes.
# The charter and the agent definitions are exempt because pointing a
# maintainer at the design notes is their entire job — they are
# addressed to someone who has the working copy. This script is exempt
# because it necessarily contains the patterns it searches for; a
# detector cannot be its own subject.
mapfile -t files < <(git ls-files |
  grep -vE '^(CLAUDE\.md|\.claude/|scripts/check_doc_refs\.sh$)')

# An empty list would make every grep below read stdin instead of files
# and report nothing, so the gate would pass by scanning nothing at all.
# Anything that empties the list — a renamed tree, a broken filter, a
# git invocation that failed inside the process substitution where its
# exit status is not observed — is a broken gate, not a clean tree.
if [ "${#files[@]}" -eq 0 ]; then
  die "no tracked files matched: the scan is broken, not the tree"
fi

# The same failure one file at a time. git ls-files reports the index,
# which can name a path the working tree no longer has — `git add`
# followed by a delete leaves one behind. grep then fails on that path
# and the `|| true` below swallows its exit status, so the file drops
# out of the scan without a word. Dropping out is counted here instead:
# a scan that cannot read what it claims to cover has not cleared it.
missing=()
for f in "${files[@]}"; do
  [ -e "$f" ] || missing+=("$f")
done
if [ "${#missing[@]}" -gt 0 ]; then
  warn "the index names ${#missing[@]} path(s) the working tree does not have:"
  printf '  %s\n' "${missing[@]}" >&2
  die "these would be skipped silently; unstage or restore them before the scan can speak for them"
fi

# A path or label that only resolves inside the working copy.
#
# The whole backup/ tree is gitignored, so every path under it is
# unresolvable for a reader of the published tree — not just the three
# subdirectories the planning notes happen to live in today. The
# trailing character class is what keeps the rule aimed at references:
# it requires a path component after the slash, so prose that names the
# directory itself ("backup/ is local working material") is not a
# citation and does not trip the gate. docs/ stays narrow because it is
# tracked and ships.
paths='backup/[A-Za-z0-9_.-]|docs/(plans|research|adr)|idm-checklist|\bplans?/[0-9]{3}-|\b[Pp]lan [0-9]{3}\b'

# A design-document section label ("§A.12.9.1", "§L.2"). Public specs
# use the same glyph, so the pattern is applied only to lines that name
# no spec: an RFC number, a W3C / OpenID document, or an ECMA / NIST
# reference is enough to clear the line.
sections='§[A-Z]\.[0-9]'
spec_bearing='RFC ?[0-9]{4}|WebAuthn|OpenID|OAuth|FAPI|ECMA|NIST|SP ?800|X\.509'

hits="$(grep -InE "$paths" "${files[@]}" || true)"
hits+=$'\n'"$(grep -InE "$sections" "${files[@]}" | grep -vE "$spec_bearing" || true)"
hits="$(printf '%s\n' "$hits" | grep -v '^$' || true)"

if [ -n "$hits" ]; then
  warn "shipped artifacts cite an internal planning document:"
  printf '%s\n' "$hits" >&2
  die "state the constraint itself, or cite a public spec"
fi

# A doc link naming an internal/ path can never resolve: godoc wants a
# full import path, and even spelled in full the package is absent from
# pkg.go.dev. The bracket text renders verbatim, so the reader is shown
# a package name they cannot open and the doc still has not said what it
# meant. Inside internal/ the working form is the imported package's own
# name — [timex.Clock], which go doc and every editor resolve — so the
# rule is the same everywhere: never put a path in the brackets.
mapfile -t go_files < <(git ls-files -- '*.go')
if [ "${#go_files[@]}" -eq 0 ]; then
  die "no tracked Go files matched: the scan is broken, not the tree"
fi
internal_links="$(grep -nE '\[[a-z0-9_.,/-]*internal/' "${go_files[@]}" || true)"
if [ -n "$internal_links" ]; then
  warn "doc links spell an internal/ path instead of a package name:"
  printf '%s\n' "$internal_links" >&2
  die "use the imported package's name, or state the behaviour without naming the package"
fi

log "doc references OK ($(printf '%s\n' "${files[@]}" | wc -l | tr -d ' ') tracked files)"
