// Module github.com/libraz/go-oidc-provider/examples/61-claims-request
// pairs the OIDC §5.5 claims-request OP with an in-process RP that
// composes the "claims" parameter. It is its own sub-module so the
// RP-side dependencies stay out of the host module's go.sum.
module github.com/libraz/go-oidc-provider/examples/61-claims-request

go 1.25.0

toolchain go1.26.5

require (
	github.com/libraz/go-oidc-provider v0.0.0-00010101000000-000000000000
	github.com/libraz/go-oidc-provider/examples/internal/rpkit v0.0.0-00010101000000-000000000000
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/coreos/go-oidc/v3 v3.11.0 // indirect
	github.com/fxamacker/cbor/v2 v2.9.2 // indirect
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/go-webauthn/webauthn v0.17.4 // indirect
	github.com/go-webauthn/x v0.2.6 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/prometheus/client_golang v1.23.2 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.66.1 // indirect
	github.com/prometheus/procfs v0.16.1 // indirect
	github.com/tinylib/msgp v1.6.4 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.yaml.in/yaml/v2 v2.4.2 // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/oauth2 v0.30.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	google.golang.org/protobuf v1.36.8 // indirect
)

replace (
	github.com/libraz/go-oidc-provider => ../..
	github.com/libraz/go-oidc-provider/examples/internal/rpkit => ../internal/rpkit
)
