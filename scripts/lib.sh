#!/usr/bin/env bash
# Shared shell helpers for scripts/.
# shellcheck shell=bash

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export REPO_ROOT

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m==>\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m==>\033[0m %s\n' "$*" >&2; exit 1; }

require_cmd() {
  local cmd="$1"
  command -v "$cmd" >/dev/null 2>&1 || die "required command not found: $cmd"
}

# Resolve a tool installed via tools/tools.go. The install directory wins
# over PATH: tools/go.mod pins the version the repository is checked
# against, and a system-wide copy (Homebrew, a distro package) is usually
# a different one. Preferring PATH would silently lint and format against
# whatever happened to be installed. PATH stays as a fallback so a
# container image that ships the tools without `make tools` still works.
tool() {
  local name="$1"
  local gobin
  gobin="$(go env GOBIN)"
  [ -z "$gobin" ] && gobin="$(go env GOPATH)/bin"
  if [ -x "$gobin/$name" ]; then
    printf '%s\n' "$gobin/$name"
    return 0
  fi
  if command -v "$name" >/dev/null 2>&1; then
    command -v "$name"
    return 0
  fi
  die "tool not installed: $name (run 'make tools')"
}

# List every Go module that ships from this repository, excluding the
# tools/ helper module (which is intentionally separate so its
# linter/build-tool dependencies do not bleed into runtime go.sum).
#
# Each line of output is "<path>\t<packages>\t<tags>":
#
#   <path>      directory to run the go command from
#   <packages>  package pattern to pass to it (usually "./...")
#   <tags>      comma-separated build-tag list, empty for the host
#               module and the storage adapters, "example" for the
#               examples and the reference application
#
# The same path may appear more than once with a different pattern and
# tag set; nothing downstream assumes one line per directory. The tag
# field is last because a tab is IFS whitespace, so `read` collapses a
# run of tabs: an empty field is only representable at end of line.
public_modules() {
  printf '%s\t./...\t\n' "$REPO_ROOT"
  if [ -f "$REPO_ROOT/op/storeadapter/sql/go.mod" ]; then
    printf '%s\t./...\t\n' "$REPO_ROOT/op/storeadapter/sql"
  fi
  if [ -f "$REPO_ROOT/op/storeadapter/redis/go.mod" ]; then
    printf '%s\t./...\t\n' "$REPO_ROOT/op/storeadapter/redis"
  fi
  if [ -f "$REPO_ROOT/op/storeadapter/dynamodb/go.mod" ]; then
    printf '%s\t./...\t\n' "$REPO_ROOT/op/storeadapter/dynamodb"
  fi
  # op-demo is its own module so the storage drivers it links for
  # -store=composite stay out of the library's dependency list. It carries
  # no build tag: the conformance harness builds it unconditionally.
  if [ -f "$REPO_ROOT/cmd/op-demo/go.mod" ]; then
    printf '%s\t./...\t\n' "$REPO_ROOT/cmd/op-demo"
  fi
  if compgen -G "$REPO_ROOT/examples/*/go.mod" >/dev/null; then
    for f in "$REPO_ROOT"/examples/*/go.mod; do
      printf '%s\t./...\t%s\n' "$(dirname "$f")" "example"
    done
  fi
  # Not every example is its own module: an example that needs no
  # dependency beyond the library is a package of the host module gated
  # behind the "example" tag, as are the helpers those examples import
  # (examples/internal/{devkeys,opkit,serve,webui}). The host module's own
  # entry above runs untagged and therefore cannot see a single one of
  # them — every file is excluded by the build constraint — so they need
  # a second pass, narrowed to the subtree that carries the tag rather
  # than re-analysing the whole module.
  printf '%s\t./examples/...\t%s\n' "$REPO_ROOT" "example"
  # Shared example helpers are independent modules too. They are not shipped
  # as tutorials, but a regression in either fans out to many examples, so the
  # normal vet/lint/build/test inventory must exercise them with the same tag.
  for d in "$REPO_ROOT/examples/internal/rpkit" "$REPO_ROOT/examples/internal/seedkit"; do
    if [ -f "$d/go.mod" ]; then
      printf '%s\t./...\t%s\n' "$d" "example"
    fi
  done
  # The reference application is its own module and carries the same build
  # tag as the examples. It builds against the working tree, so a change
  # that breaks an embedder-facing seam breaks it in the same commit.
  if [ -f "$REPO_ROOT/sample/go.mod" ]; then
    printf '%s\t./...\t%s\n' "$REPO_ROOT/sample" "example"
  fi
  verify_harness_modules
}

# The example verification harnesses. Both modules consist entirely of
# build-tagged test files: apiverify boots each non-browser example over plain
# HTTP, browserverify drives the browser examples through a headless Chrome.
#
# They belong in the vet/lint/build inventory so a harness that stops
# compiling fails like any other code in the tree. Their *tests* are a
# different matter: running them builds and boots every example as a real
# process, which takes minutes and (for browserverify) needs a browser. So
# scripts/test.sh skips them and scripts/verify_example_harness.sh — `make
# verify-examples-api` / `-browser` / `-harness` — runs them instead.
#
# The build tag also keeps them out of the go.work member list, which
# scripts/workspace.sh derives from the untagged entries of this inventory.
verify_harness_modules() {
  if [ -f "$REPO_ROOT/examples/internal/apiverify/go.mod" ]; then
    printf '%s\t./...\t%s\n' "$REPO_ROOT/examples/internal/apiverify" "apiverify"
  fi
  if [ -f "$REPO_ROOT/examples/internal/browserverify/go.mod" ]; then
    printf '%s\t./...\t%s\n' "$REPO_ROOT/examples/internal/browserverify" "browserverify"
  fi
}

# The build tools that back the repository's own gates: the scenario
# catalog validator and the stability reporter. They are separate modules
# so their parsing dependencies stay out of the library's go.sum, and they
# are deliberately not part of public_modules — nothing here ships, and an
# untagged entry there would also enrol them in go.work.
#
# They are still first-class code: a gate is worth no more than the tool
# behind it, so they carry the same lint and vet bar as everything else.
# The inventory is a function rather than a literal list at each call site
# so a tool added later is picked up by every consumer at once.
#
# Output format matches public_modules, minus the tag field: these modules
# have no build-tagged files. Callers must run `go`/golangci-lint with
# GOWORK=off — go.work lists neither module, and a workspace that does not
# contain the directory makes golangci-lint report no findings at all
# rather than fail, which is how these two went unlinted.
tool_modules() {
  local d
  for d in scenariotool stabilitytool; do
    if [ -f "$REPO_ROOT/tools/$d/go.mod" ]; then
      printf '%s\t./...\n' "$REPO_ROOT/tools/$d"
    fi
  done
}

# is_verify_harness_module reports whether a module directory is one of the
# entries verify_harness_modules emits.
is_verify_harness_module() {
  local want="$1" mod
  while IFS=$'\t' read -r mod _; do
    [ "$mod" = "$want" ] && return 0
  done < <(verify_harness_modules)
  return 1
}

# go_args_for echoes "-tags=<csv>" when the second argument is
# non-empty, suitable for unquoted expansion in `go` commands.
go_args_for() {
  local tags="$1"
  [ -z "$tags" ] && return 0
  printf '%s' "-tags=$tags"
}
