#!/usr/bin/env bash
# Wrapper around tools/gatetool — the gate-topology check.
#
# The tool is a separate Go module under tools/gatetool/ so it can run
# while the main module is mid-edit. It reads test/gates/gates.yaml and
# reconciles it against the tree, then renders api/gates.md.
#
# See the tool's package doc for what each of the three checks asserts.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

# The tool module is deliberately outside the shipping inventory, so it
# is also outside any workspace a release or CI run creates.
export GOWORK=off

cd "$REPO_ROOT/tools/gatetool"

exec go run . -root "$REPO_ROOT" "$@"
