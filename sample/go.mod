// Module github.com/libraz/go-oidc-provider/sample is the reference
// application: an embedder-owned account system (signup, login, TOTP
// enrolment) fronting the OP, on the storage shape a deployment actually
// runs — MySQL for the durable substores and the application's own tables,
// Redis for the volatile ones.
//
// It is its own Go module so the MySQL and Redis drivers stay out of the
// library's go.sum, the same arrangement the examples use.
module github.com/libraz/go-oidc-provider/sample

go 1.25.0

toolchain go1.27.0

require (
	github.com/coreos/go-oidc/v3 v3.20.0
	github.com/go-sql-driver/mysql v1.10.0
	github.com/libraz/go-oidc-provider v1.1.0
	github.com/libraz/go-oidc-provider/op/storeadapter/redis v1.1.0
	github.com/libraz/go-oidc-provider/op/storeadapter/sql v1.1.0
	golang.org/x/crypto v0.55.0
	golang.org/x/oauth2 v0.36.0
)

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/fxamacker/cbor/v2 v2.9.3 // indirect
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/go-webauthn/webauthn v0.18.0 // indirect
	github.com/go-webauthn/x v0.3.0 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/pgx/v5 v5.10.0 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/prometheus/client_golang v1.24.1 // indirect
	github.com/prometheus/client_model v0.6.3 // indirect
	github.com/prometheus/common v0.71.0 // indirect
	github.com/prometheus/procfs v0.22.0 // indirect
	github.com/redis/go-redis/v9 v9.22.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/tinylib/msgp v1.6.4 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
	modernc.org/libc v1.75.6 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.12.1 // indirect
	modernc.org/sqlite v1.57.0 // indirect
)

replace (
	github.com/libraz/go-oidc-provider => ..
	github.com/libraz/go-oidc-provider/op/storeadapter/redis => ../op/storeadapter/redis
	github.com/libraz/go-oidc-provider/op/storeadapter/sql => ../op/storeadapter/sql
)
