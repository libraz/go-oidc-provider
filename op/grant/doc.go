// Package grant enumerates the OAuth 2.0 grant_type values understood by the
// [op.Provider]. Callers select grants explicitly via [op.WithGrants]; the
// library refuses to mint tokens for any grant_type not in the enabled set.
//
// The package is type-only on purpose. Each grant_type is a [Type] value, not
// a string, so the compiler rejects arbitrary input at the configuration site
// rather than the token endpoint.
package grant
