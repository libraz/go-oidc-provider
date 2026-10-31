// Module failopentool implements the fail-open gate used by
// scripts/failopen.sh and `make failopen`. It parses sources rather
// than building them so the gate can run while the main module is
// mid-edit, and it depends on nothing outside the standard library and
// tools/internal/gatekit.
module github.com/libraz/go-oidc-provider/tools/failopentool

go 1.25.0

toolchain go1.27.3

require github.com/libraz/go-oidc-provider/tools/internal/gatekit v0.0.0

replace github.com/libraz/go-oidc-provider/tools/internal/gatekit => ../internal/gatekit
