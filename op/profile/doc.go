// Package profile enumerates the industry security profiles that an
// [op.Provider] may opt into via [op.WithProfile]. A profile is a curated
// bundle of [github.com/libraz/go-oidc-provider/op/feature.Flag] values, alg
// constraints, and policy switches drawn from a published specification
// (OAuth 2.1, FAPI, …).
//
// Profiles compose multiplicatively: enabling [FAPI2Baseline] is equivalent
// to enabling its underlying features and policies in one call. A profile
// MUST NOT be relaxed by a later option; the library rejects [op.New]
// configurations whose options would weaken an enabled profile.
//
// A profile constrains the two neighbouring declaration axes differently.
// Missing features ([RequiredFeatures], [RequiredAnyOf]) are supplied
// automatically, because a feature flag is policy the profile is entitled to
// decide. Missing grants ([RequiredGrants]) fail [op.New] instead, because a
// grant drags in wiring only the embedder can provide — the library does not
// switch on an endpoint the deployment never asked to serve.
//
// Selecting no profile is the same as selecting [OAuth21]. A deployment that
// must admit authorization-code requests without a code_challenge (the
// OpenID Connect Core 1.0 shape, which predates RFC 7636) declares
// [OIDCCore] explicitly; it cannot be combined with another profile.
package profile
