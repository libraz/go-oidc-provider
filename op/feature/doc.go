// Package feature enumerates the optional protocol extensions that an
// [op.Provider] may opt into via [op.WithFeature]. Each feature corresponds
// to a discrete RFC or OpenID specification; enabling one wires up its
// endpoints, validators, and discovery metadata.
//
// The package is type-only on purpose. Each feature is a [Flag] value, not a
// string, so the compiler rejects arbitrary input at the configuration site
// rather than at runtime.
package feature
