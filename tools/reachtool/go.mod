// Module reachtool implements the declared-but-unreached gate used by
// scripts/reach.sh and `make reach`. It is a separate Go module so the
// gate can be built and run while the main module is mid-edit, and it
// depends on nothing outside the standard library and tools/internal/gatekit.
module github.com/libraz/go-oidc-provider/tools/reachtool

go 1.25.0

toolchain go1.27.3

require github.com/libraz/go-oidc-provider/tools/internal/gatekit v0.0.0

replace github.com/libraz/go-oidc-provider/tools/internal/gatekit => ../internal/gatekit
