#!/usr/bin/env bash
# Install developer tools pinned in tools/tools.go.
#
# tools/ is a sibling module so its dependencies (golangci-lint, gofumpt,
# goimports, govulncheck, go-licenses) do not bleed into the main go.mod.
# We resolve the pinned versions from tools/go.mod and install each one.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"

require_cmd go

log "Installing tools pinned in tools/go.mod"
cd "$REPO_ROOT/tools"

# Extract the tool main-package import paths from tools.go (lines like
# `_ "path/to/main"`). We avoid `go list .Imports` because `go list` rejects
# main packages, and we keep the source of truth in tools.go itself rather
# than duplicating it into this script.
mapfile -t pkgs < <(
  awk '
    /^[[:space:]]*_[[:space:]]+"/ {
      match($0, /"[^"]+"/)
      if (RSTART > 0) {
        print substr($0, RSTART + 1, RLENGTH - 2)
      }
    }
  ' tools.go
)

if [ "${#pkgs[@]}" -eq 0 ]; then
  warn "no tools found in tools/tools.go"
  exit 0
fi

for pkg in "${pkgs[@]}"; do
  log "go install $pkg"
  go install "$pkg"
done

log "Tools installed to $(go env GOBIN || echo "$(go env GOPATH)/bin")"
