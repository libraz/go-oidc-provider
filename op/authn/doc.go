// Package authn declares the authentication contract types an embedder
// implements or reads: the [Authenticator] and [Interaction] interfaces and
// their inputs, [FactorType] and [AAL], the risk and captcha seams, and the
// login-attempt feed.
//
// Every name here is re-exported from package op
// ([github.com/libraz/go-oidc-provider/op]) as a type alias, so embedders
// write op.Authenticator and the two spellings denote the same type. The
// package exists as a separate leaf only so that the library's internal
// packages can share these declarations without importing op.
package authn
