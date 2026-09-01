// Module failopentool implements the fail-open gate used by
// scripts/failopen.sh and `make failopen`. It parses sources rather
// than building them so the gate can run while the main module is
// mid-edit, and it depends on nothing outside the standard library.
module github.com/libraz/go-oidc-provider/tools/failopentool

go 1.25.0

toolchain go1.27.0
