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
# 6. Every op symbol a demo comment names is one package op exports.
# 7. The hot/cold store examples route the Kinds their comments claim.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

cd "$REPO_ROOT"

test_parallel="$(go_test_parallelism)"
go_max_procs="${GOMAXPROCS:-$test_parallel}"
log "example-build parallelism: packages=$test_parallel, GOMAXPROCS=$go_max_procs (override GO_TEST_PARALLEL or GOMAXPROCS)"

# Most examples are their own module, and `go` does not descend into a
# nested module, so a single ./examples/... pattern from the repository
# root compiles only the handful that are packages of the host module.
# Iterating the shared inventory is what makes this target cover the same
# set `make verify` does — an example edited by the contributor running
# it included.
while IFS=$'\t' read -r mod pkgs tags; do
  args="$(go_args_for "$tags")"
  # Every entry the inventory emits here carries the tag; without it the
  # empty expansion would reach `go` as an empty argument.
  [ -n "$args" ] || die "example inventory entry with no build tag: $mod $pkgs"
  log "go build $args $pkgs ($mod)"
  (cd "$mod" && GOWORK=off GOMAXPROCS="$go_max_procs" go build -p "$test_parallel" "$args" "$pkgs")
  log "go vet $args $pkgs ($mod)"
  (cd "$mod" && GOWORK=off GOMAXPROCS="$go_max_procs" go vet -p "$test_parallel" "$args" "$pkgs")
done < <(example_modules)

"$SCRIPT_DIR/check_example_endpoints.sh"
"$SCRIPT_DIR/check_example_pkce.sh"
"$SCRIPT_DIR/check_example_secrets.sh"
"$SCRIPT_DIR/check_example_dev_optins.sh"
"$SCRIPT_DIR/check_example_symbols.sh"
"$SCRIPT_DIR/check_example_store_parity.sh"

log "verify-examples OK"
