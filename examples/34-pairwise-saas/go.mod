// Module github.com/libraz/go-oidc-provider/examples/34-pairwise-saas
// pairs a single OP with two tenant Relying Parties whose redirect
// URIs resolve to distinct sector hosts so the OIDC Core 1.0 §8.1
// pairwise subject derivation produces different "sub" values for
// the same end-user across the two tenants. It is its own sub-module
// so the example tree stays buildable in isolation and the host
// module's go.sum is unaffected.
module github.com/libraz/go-oidc-provider/examples/34-pairwise-saas

go 1.25.0

require github.com/libraz/go-oidc-provider v0.0.0-00010101000000-000000000000

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/fxamacker/cbor/v2 v2.9.0 // indirect
	github.com/go-jose/go-jose/v4 v4.1.2 // indirect
	github.com/go-webauthn/webauthn v0.13.4 // indirect
	github.com/go-webauthn/x v0.1.23 // indirect
	github.com/golang-jwt/jwt/v5 v5.2.3 // indirect
	github.com/google/go-tpm v0.9.5 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/prometheus/client_golang v1.23.2 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.66.1 // indirect
	github.com/prometheus/procfs v0.16.1 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.yaml.in/yaml/v2 v2.4.2 // indirect
	golang.org/x/crypto v0.40.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.35.0 // indirect
	google.golang.org/protobuf v1.36.8 // indirect
)

replace github.com/libraz/go-oidc-provider => ../..
