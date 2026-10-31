// Module gatekit holds the source walk and allowlist loader the gate
// tools under tools/ share. It is a separate module because each of
// those tools is one, and it depends on nothing outside the standard
// library.
module github.com/libraz/go-oidc-provider/tools/internal/gatekit

go 1.25.0

toolchain go1.27.3
