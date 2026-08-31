#!/usr/bin/env bash
# Wrapper around tools/reachtool — the declared-but-unreached gate.
#
# The tool is a separate Go module under tools/reachtool/ so it can be
# built and run while the main module is mid-edit; it parses sources
# rather than building them for the same reason. We invoke it with
# `go run` from that directory and inject the repository root, which is
# also where it resolves api/unreached.txt from.
#
# See the tool's package doc for what each of the four checks asserts
# and for what belongs in the allowlist.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

# The tool module is deliberately outside the shipping inventory, so it
# is also outside any workspace a release or CI run creates. Workspace
# mode would refuse to build a directory the workspace does not use.
export GOWORK=off

cd "$REPO_ROOT/tools/reachtool"

exec go run . -root "$REPO_ROOT" "$@"
