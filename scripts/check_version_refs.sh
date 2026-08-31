#!/usr/bin/env bash
# Assert every shipped version literal names the current release.
#
# The install instructions, the README status line, and the require
# directives of the in-repo modules are three copies of one fact, updated
# by hand at three different moments. They drifted: a reader following
# one install block got a release older than the one the neighbouring
# prose promised, and older than the code beside it needed. For a
# security-relevant library that is not a cosmetic mismatch — it hands
# the reader a version without the fixes the current one ships.
#
# The current release is read off CHANGELOG.md rather than `git tag`,
# because the changelog is checked in and a shallow CI clone has no tags.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

cd "$REPO_ROOT"

# The newest released heading. "## [Unreleased]" carries no version and
# is skipped by the pattern.
release="$(grep -oE '^## \[v[0-9]+\.[0-9]+\.[0-9]+\]' CHANGELOG.md | head -1 |
  sed -E 's/^## \[(v[0-9]+\.[0-9]+\.[0-9]+)\]/\1/')"
if [ -z "$release" ]; then
  die "no released version heading in CHANGELOG.md: the scan is broken, not the tree"
fi

bad=()

# 1. Documentation. Two positions speak for the current release: an
# install line (@vX.Y.Z) and the status banner each README opens with.
# Every other version a page mentions is history — "the release that
# follows v0.9.0" — and stays whatever it was, so the scan is aimed at
# the two positions rather than at every version literal on the page.
docs=(README.md README_ja.md examples/README.md)
for doc in "${docs[@]}"; do
  [ -f "$doc" ] || die "$doc is missing: the scan is broken, not the tree"
  while IFS= read -r hit; do
    [ -z "$hit" ] && continue
    bad+=("$doc:$hit")
  done < <(grep -nE '@v[0-9]+\.[0-9]+\.[0-9]+|(Status|ステータス): *`v[0-9]+\.[0-9]+\.[0-9]+`' "$doc" |
    grep -vE "(@|\`)${release}([^0-9]|$)" || true)
done

# The status banner is the half that silently rots: nothing links it to
# a release step, and a README with none at all would clear the scan
# above by having nothing to check.
for doc in README.md README_ja.md; do
  if ! grep -qE '(Status|ステータス): *`v[0-9]+\.[0-9]+\.[0-9]+`' "$doc"; then
    die "$doc has no status banner naming a version: the scan is broken, not the tree"
  fi
done

# 2. Module manifests. Every in-repo module that requires the library or
# one of its storage adapters pins a version, and the same-tag release
# policy means all of them name one release. A replace directive has no
# version, so the require lines are the whole surface.
mapfile -t manifests < <(git ls-files -- '*go.mod')
if [ "${#manifests[@]}" -eq 0 ]; then
  die "no tracked go.mod matched: the scan is broken, not the tree"
fi
while IFS= read -r hit; do
  [ -z "$hit" ] && continue
  bad+=("$hit")
done < <(grep -nE '^[[:space:]]*(require )?github\.com/libraz/go-oidc-provider(/op/storeadapter/[a-z]+)? v[0-9]' "${manifests[@]}" |
  grep -vE " ${release}\$" || true)

if [ "${#bad[@]}" -gt 0 ]; then
  warn "version literals disagree with the current release ($release):"
  printf '  %s\n' "${bad[@]}" >&2
  die "point every install instruction and require at $release, or cut the release first"
fi
log "version references OK (everything names $release)"
