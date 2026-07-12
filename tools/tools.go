//go:build tools

// Package tools enumerates the CLI tools pinned by the repository. None of
// the imports below are used at runtime; the `tools` build tag keeps them
// out of normal builds while letting `go.mod` record exact versions.
package tools

import (
	_ "github.com/golangci/golangci-lint/v2/cmd/golangci-lint"
	_ "golang.org/x/tools/cmd/goimports"
	_ "golang.org/x/vuln/cmd/govulncheck"
	_ "mvdan.cc/gofumpt"
)
