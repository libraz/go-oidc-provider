// Module github.com/libraz/go-oidc-provider/examples/08-composite-hot-cold
// demonstrates the composite hot/cold storage split (SQL durable, fast
// volatile). It is its own sub-module so the SQL driver dependency stays
// out of the main module's go.sum.
module github.com/libraz/go-oidc-provider/examples/08-composite-hot-cold

go 1.25.0

require (
	github.com/libraz/go-oidc-provider v0.0.0-00010101000000-000000000000
	github.com/libraz/go-oidc-provider/op/storeadapter/sql v0.0.0-00010101000000-000000000000
	modernc.org/sqlite v1.50.0
)

require (
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/fxamacker/cbor/v2 v2.9.0 // indirect
	github.com/go-jose/go-jose/v4 v4.1.2 // indirect
	github.com/go-webauthn/webauthn v0.13.4 // indirect
	github.com/go-webauthn/x v0.1.23 // indirect
	github.com/golang-jwt/jwt/v5 v5.2.3 // indirect
	github.com/google/go-tpm v0.9.5 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/prometheus/client_golang v1.23.2 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.66.1 // indirect
	github.com/prometheus/procfs v0.16.1 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.yaml.in/yaml/v2 v2.4.2 // indirect
	golang.org/x/crypto v0.48.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	google.golang.org/protobuf v1.36.8 // indirect
	modernc.org/libc v1.72.0 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)

replace (
	github.com/libraz/go-oidc-provider => ../..
	github.com/libraz/go-oidc-provider/op/storeadapter/sql => ../../op/storeadapter/sql
)
