// Module github.com/libraz/go-oidc-provider/examples/34-pairwise-saas
// pairs a single OP with two tenant Relying Parties whose redirect
// URIs resolve to distinct sector hosts so the OIDC Core 1.0 §8.1
// pairwise subject derivation produces different "sub" values for
// the same end-user across the two tenants. It is its own sub-module
// so the example tree stays buildable in isolation and the host
// module's go.sum is unaffected.
module github.com/libraz/go-oidc-provider/examples/34-pairwise-saas

go 1.25.0

toolchain go1.26.5

require github.com/libraz/go-oidc-provider v1.1.0

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/fxamacker/cbor/v2 v2.9.2 // indirect
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/go-webauthn/webauthn v0.17.4 // indirect
	github.com/go-webauthn/x v0.2.8 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/prometheus/client_golang v1.24.1 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.70.1 // indirect
	github.com/prometheus/procfs v0.21.1 // indirect
	github.com/tinylib/msgp v1.6.4 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/crypto v0.55.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)

replace github.com/libraz/go-oidc-provider => ../..
