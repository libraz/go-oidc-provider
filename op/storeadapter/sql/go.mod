// Module github.com/libraz/go-oidc-provider/op/storeadapter/sql is the SQL
// storage adapter for go-oidc-provider. It is published as a sub-module so
// that the database/sql driver dependencies (mysql, pgx, modernc.org/sqlite)
// stay out of the main module's go.sum.
module github.com/libraz/go-oidc-provider/op/storeadapter/sql

go 1.25.0

require (
	github.com/libraz/go-oidc-provider v0.0.0-00010101000000-000000000000
	modernc.org/sqlite v1.50.0
)

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/sys v0.42.0 // indirect
	modernc.org/libc v1.72.0 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)

// During development the sub-module pulls the host module from the local
// checkout so changes to op/store interfaces can be exercised without a
// release. Released tags pin a real version through go.sum and the replace
// is removed by the release pipeline.
replace github.com/libraz/go-oidc-provider => ../../..
