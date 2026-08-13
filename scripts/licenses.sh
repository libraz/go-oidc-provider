#!/usr/bin/env bash
# Verify dependency licenses against the project allowlist, and
# regenerate THIRD_PARTY.md across the host module and every
# storage-adapter sub-module.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

cd "$REPO_ROOT"

# go-licenses is pinned here rather than in tools/go.mod: v1.6.0 depends on an
# older otiai10/copy API than golangci-lint requires, so the two cannot share a
# module. `go run <pkg>@<version>` builds it in its own module graph, sidestepping
# that conflict while keeping the version pinned. (go-licenses/v2 is unusable —
# it treats the Go 1.26 standard library as "non go modules" and aborts.)
GOLICENSES_VERSION="v1.6.0"
GO_LICENSES=(go run "github.com/google/go-licenses@${GOLICENSES_VERSION}")

# The licenses this project accepts, as SPDX identifiers, matched exactly.
#
# The gate is an allowlist rather than a list of forbidden families, because
# the failure that matters is not "a dependency arrived under a license we
# named" — it is "a dependency arrived under a license nobody classified".
# A denylist passes the unclassified case, passes a spelling nobody
# anticipated (`GPL-1.0` is not `GPL-2` or `GPL-3`), and cannot be told apart
# from a pattern that matches nothing at all. Requiring a positive match
# turns every one of those into a failure that names the module.
#
# Everything here is permissive or file-scoped copyleft, so linking the
# library imposes no obligation on the embedder's own sources beyond notice
# retention. Adding an entry is a licensing decision, not a build fix.
ALLOWED_LICENSES=(
  Apache-2.0
  BSD-2-Clause
  BSD-3-Clause
  ISC
  MIT
  MPL-2.0
)

# Classifications the scanner cannot make, resolved by reading the module's
# own license file.
#
# go-licenses reports a license only when the classifier clears its
# confidence threshold, so a module that restates permissive terms in its
# own words instead of copying the canonical text comes back as `Unknown`.
# Lowering the threshold would weaken every other row, so the classification
# is pinned per module instead. An override still has to name a license the
# allowlist accepts — it corrects what the scanner could not read, it does
# not grant an exemption.
#
# Fields are `<module path>|<SPDX id>|<source URL>`. The URL is the module's
# license page rather than a tag-pinned blob, because the scanner supplies no
# URL for these rows and a hand-written tag would go stale at the next bump.
LICENSE_OVERRIDES=(
  # modernc.org/mathutil ships a three-clause BSD license (retain the notice
  # in source, reproduce it in binary form, no endorsement) rewritten in the
  # authors' own wording.
  'modernc.org/mathutil|BSD-3-Clause|https://pkg.go.dev/modernc.org/mathutil?tab=licenses'
)

# The repository's own modules, as a line anchor for the report. The storage
# adapters ship no license file of their own — the root LICENSE states the
# terms for every module in the tree — so the scanner cannot classify them,
# and they are not a third-party question to begin with. Both the gate and
# the generated index drop them through the same filter, so neither can
# start judging rows the other leaves out.
SELF_MODULE_RE='^github\.com/libraz/go-oidc-provider'

# third_party_rows writes a report to stdout with the project's own modules
# removed.
third_party_rows() {
  grep -v "$SELF_MODULE_RE" "$1" || true
}

# is_allowed_license reports whether an SPDX identifier is on the allowlist.
# The comparison is exact: a substring or prefix test is how an unrelated
# column, or a version suffix nobody expected, decides the gate.
is_allowed_license() {
  local want="$1" allowed
  for allowed in "${ALLOWED_LICENSES[@]}"; do
    [ "$want" = "$allowed" ] && return 0
  done
  return 1
}

# apply_overrides writes a go-licenses report to stdout with each overridden
# module's license and source replaced.
apply_overrides() {
  local report="$1" mod link lic entry key spdx url
  while IFS=, read -r mod link lic || [ -n "$mod" ]; do
    [ -z "$mod" ] && continue
    for entry in "${LICENSE_OVERRIDES[@]}"; do
      IFS='|' read -r key spdx url <<< "$entry"
      if [ "$mod" = "$key" ]; then
        link="$url"
        lic="$spdx"
        break
      fi
    done
    printf '%s,%s,%s\n' "$mod" "$link" "$lic"
  done < "$report"
}

# check_report measures every row of a go-licenses report against the
# allowlist and reports failure if any row is left unaccounted for.
#
# The report's columns are module path, license URL and license, in that
# order, so the license is the third field. Reading it positionally is what
# keeps the decision on the license: a pattern applied to the whole line
# matches module paths and URLs too, and one anchored to the start of a line
# never reaches the license column at all.
check_report() {
  local report="$1" mod lic rejected=0
  while IFS=, read -r mod _ lic || [ -n "$mod" ]; do
    [ -z "$mod" ] && continue
    if ! is_allowed_license "$lic"; then
      warn "license not on the allowlist: $mod is classified as ${lic:-<empty>}"
      rejected=1
    fi
  done < <(third_party_rows "$report" | sort -u)
  return "$rejected"
}

# gate_report resolves the overrides into a report in place, then fails the
# run unless every dependency it lists is positively allowed.
gate_report() {
  local report="$1" resolved
  resolved="$(mktemp)"
  apply_overrides "$report" > "$resolved"
  mv "$resolved" "$report"
  if ! check_report "$report"; then
    die "dependency license is not on the project allowlist (see above)"
  fi
  log "All dependencies pass the license allowlist."
}

# `--check <report>` runs the classification half of this script over an
# existing go-licenses report: overrides are applied, every row is measured
# against the allowlist, and nothing is scanned or rewritten. Collecting the
# report needs the full module graph and a network fetch; deciding on it
# needs neither. Without this split the gate could only ever be exercised by
# the run it guards, which is to say never against an input that must fail.
if [ "${1:-}" = "--check" ]; then
  [ "$#" -eq 2 ] || die "usage: licenses.sh --check <go-licenses.csv>"
  [ -f "$2" ] || die "report not found: $2"
  CHECKED="$(mktemp)"
  trap 'rm -f "$CHECKED"' EXIT
  cp "$2" "$CHECKED"
  gate_report "$CHECKED"
  exit 0
fi

MERGED=/tmp/go-licenses.csv
: > "$MERGED"

run_module() {
  local mod="$1"
  local tags="${2:-}"
  if [ -n "$tags" ]; then
    log "go-licenses csv ./... ($mod, tags=$tags)"
    ( cd "$mod" && GOFLAGS="-tags=$tags" "${GO_LICENSES[@]}" csv ./... 2>/dev/null ) >> "$MERGED"
  else
    log "go-licenses csv ./... ($mod)"
    ( cd "$mod" && "${GO_LICENSES[@]}" csv ./... 2>/dev/null ) >> "$MERGED"
  fi
}

# Host module is always inspected. Storage-adapter sub-modules are
# inspected when present so their driver dependencies (mysql, pgx,
# sqlite, go-redis) appear in the canonical THIRD_PARTY.md. Example
# sub-modules are deliberately skipped: they pull in the same drivers
# transitively through the adapters they import, so adding them would
# only duplicate rows and surface tooling-only deps that the user
# never imports.
run_module "$REPO_ROOT"
if [ -f "$REPO_ROOT/op/storeadapter/sql/go.mod" ]; then
  # The SQL adapter does not import any driver itself — embedders
  # pick the engine and pass an open *sql.DB. The drivers
  # (modernc.org/sqlite, mysql, pgx) are surfaced via a build-tagged
  # licenses_drivers.go file gated by `//go:build licenses`, which is
  # compiled only by this script so the driver licenses appear in the
  # canonical THIRD_PARTY index without polluting regular builds.
  run_module "$REPO_ROOT/op/storeadapter/sql" licenses
fi
if [ -f "$REPO_ROOT/op/storeadapter/redis/go.mod" ]; then
  run_module "$REPO_ROOT/op/storeadapter/redis"
fi
if [ -f "$REPO_ROOT/op/storeadapter/dynamodb/go.mod" ]; then
  run_module "$REPO_ROOT/op/storeadapter/dynamodb"
fi

gate_report "$MERGED"

# Regenerate THIRD_PARTY.md from the merged report so the committed
# index never drifts from go.mod across the public modules. Rows are
# deduplicated and sorted lexicographically for a stable diff.
# Regeneration is a manual step (`make licenses`); no CI job runs it,
# so the committed index is only as fresh as the last run. The gate
# above is what refuses an unclassifiable dependency, and it runs on
# the freshly-collected report rather than on the committed file.
INDEX="$REPO_ROOT/THIRD_PARTY.md"
{
  printf '# Third-Party Licenses\n\n'
  printf 'This file is generated by `scripts/licenses.sh` from `go-licenses csv ./...` runs '
  printf 'across the host module and every storage-adapter sub-module '
  printf '(`op/storeadapter/sql`, `op/storeadapter/redis`, `op/storeadapter/dynamodb`). '
  printf 'Do not edit by hand — run `make licenses` to regenerate.\n\n'
  printf 'The project itself is licensed under Apache-2.0 (see `LICENSE` and `NOTICE` at the repo root).\n\n'
  printf '## Go module dependencies\n\n'
  printf '| Module | License | Source |\n'
  printf '|---|---|---|\n'
  third_party_rows "$MERGED" \
    | sort -u \
    | while IFS=, read -r mod link lic; do
        printf '| `%s` | %s | <%s> |\n' "$mod" "$lic" "$link"
      done
} > "$INDEX"
log "Wrote $INDEX"
