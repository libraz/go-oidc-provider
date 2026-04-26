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
