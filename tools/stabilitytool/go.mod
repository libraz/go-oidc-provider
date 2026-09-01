// Module stabilitytool reports the SemVer-exempt public surface: every
// exported symbol whose godoc carries an "Experimental:" marker. It is a
// separate Go module so it can depend on go/ast tooling without adding
// anything to the main module's go.sum.
module github.com/libraz/go-oidc-provider/tools/stabilitytool

go 1.25.0

toolchain go1.27.0
