#!/usr/bin/env bash
# Aggregate verification for the examples/ tree. Run by `make
# verify-examples` and from `make verify`.
#
# 1. Every example compiles under -tags example.
# 2. Documented /oidc/* paths match op/endpoints.go defaults.
# 3. PKCE shell snippets produce base64url, not hex.
# 4. No two examples share a client-secret literal.
# 5. No example carries a development opt-in it does not need, and the
#    READMEs count the ones that do correctly.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

cd "$REPO_ROOT"

log "go build -tags example ./examples/..."
GOWORK=off go build -tags example ./examples/...

log "go vet -tags example ./examples/..."
GOWORK=off go vet -tags example ./examples/...

"$SCRIPT_DIR/check_example_endpoints.sh"
"$SCRIPT_DIR/check_example_pkce.sh"
"$SCRIPT_DIR/check_example_secrets.sh"
"$SCRIPT_DIR/check_example_dev_optins.sh"

log "verify-examples OK"
