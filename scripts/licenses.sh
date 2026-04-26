#!/usr/bin/env bash
# Verify dependency licenses against the project allowlist.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

cd "$REPO_ROOT"

LICENSES="$(tool go-licenses)"

# Disallowed: AGPL, GPL (any), SSPL, BUSL, Elastic, Commons Clause.
disallowed_re='AGPL|^GPL|GPL-2|GPL-3|SSPL|BUSL|Elastic|Commons-Clause'

log "go-licenses report ./..."
"$LICENSES" report ./... 2>/dev/null | tee /tmp/go-licenses.csv

if grep -E "$disallowed_re" /tmp/go-licenses.csv >/dev/null; then
  die "disallowed license detected (see above)"
fi

log "All dependencies pass license allowlist."
