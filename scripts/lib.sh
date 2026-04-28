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

# Resolve a tool installed via tools/tools.go. Falls back to PATH.
tool() {
  local name="$1"
  if command -v "$name" >/dev/null 2>&1; then
    command -v "$name"
    return 0
  fi
  local gobin
  gobin="$(go env GOBIN)"
  [ -z "$gobin" ] && gobin="$(go env GOPATH)/bin"
  if [ -x "$gobin/$name" ]; then
    printf '%s\n' "$gobin/$name"
    return 0
  fi
  die "tool not installed: $name (run 'make tools')"
}

# List every Go module that ships from this repository, excluding the
# tools/ helper module (which is intentionally separate so its
# linter/build-tool dependencies do not bleed into runtime go.sum).
#
# Each line of output is "<path>\t<tags>" where <tags> is a
# comma-separated build-tag list to apply when running go commands
# inside that module (empty for the host module and storage adapters,
# "example" for example sub-modules whose main.go is gated).
public_modules() {
  printf '%s\t\n' "$REPO_ROOT"
  if [ -f "$REPO_ROOT/op/storeadapter/sql/go.mod" ]; then
    printf '%s\t\n' "$REPO_ROOT/op/storeadapter/sql"
  fi
  if compgen -G "$REPO_ROOT/examples/*/go.mod" >/dev/null; then
    for f in "$REPO_ROOT"/examples/*/go.mod; do
      printf '%s\t%s\n' "$(dirname "$f")" "example"
    done
  fi
}

# go_args_for echoes "-tags=<csv>" when the second argument is
# non-empty, suitable for unquoted expansion in `go` commands.
go_args_for() {
  local tags="$1"
  [ -z "$tags" ] && return 0
  printf '%s' "-tags=$tags"
}
