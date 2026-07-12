// Module github.com/libraz/go-oidc-provider/examples/internal/rpkit
// is the minimal Relying Party shared by example/* main.go files
// that pair an in-process RP with the OP they boot. It is its own
// sub-module so its dependencies (golang.org/x/oauth2,
// github.com/coreos/go-oidc/v3) stay out of the host module's
// go.sum. Examples that import rpkit add their own replace directive
// pointing at this directory; see examples/01-minimal for the
// canonical wiring.
module github.com/libraz/go-oidc-provider/examples/internal/rpkit

go 1.25.0

toolchain go1.26.5

require (
	github.com/coreos/go-oidc/v3 v3.11.0
	github.com/go-jose/go-jose/v4 v4.0.2
	golang.org/x/oauth2 v0.24.0
)

require golang.org/x/crypto v0.53.0 // indirect
