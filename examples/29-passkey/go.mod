// Module github.com/libraz/go-oidc-provider/examples/29-passkey
// demonstrates the passkey lifecycle: WebAuthn enrolment through
// op/passkeykit on a page the example owns, then login through
// op.PrimaryPasskey, against an in-process RP built on
// examples/internal/rpkit with the user seeded through
// examples/internal/seedkit. It is its own sub-module so the demo-only
// helper dependencies stay out of the library's go.sum.
module github.com/libraz/go-oidc-provider/examples/29-passkey

go 1.25.0

toolchain go1.27.0

require (
	github.com/libraz/go-oidc-provider v1.2.0
	github.com/libraz/go-oidc-provider/examples/internal/rpkit v0.0.0-20260727001405-2d3c5fc0c0bf
	github.com/libraz/go-oidc-provider/examples/internal/seedkit v0.0.0-20260727001405-2d3c5fc0c0bf
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/coreos/go-oidc/v3 v3.20.0 // indirect
	github.com/fxamacker/cbor/v2 v2.9.3 // indirect
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/go-webauthn/webauthn v0.18.0 // indirect
	github.com/go-webauthn/x v0.3.0 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/prometheus/client_golang v1.24.1 // indirect
	github.com/prometheus/client_model v0.6.3 // indirect
	github.com/prometheus/common v0.71.0 // indirect
	github.com/prometheus/procfs v0.22.0 // indirect
	github.com/tinylib/msgp v1.6.4 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/crypto v0.55.0 // indirect
	golang.org/x/oauth2 v0.36.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
	rsc.io/qr v0.2.0 // indirect
)

replace (
	github.com/libraz/go-oidc-provider => ../..
	github.com/libraz/go-oidc-provider/examples/internal/rpkit => ../internal/rpkit
	github.com/libraz/go-oidc-provider/examples/internal/seedkit => ../internal/seedkit
)
