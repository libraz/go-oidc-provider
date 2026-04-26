// Package profile enumerates the industry security profiles that an
// [op.Provider] may opt into via [op.WithProfile]. A profile is a curated
// bundle of [op.feature.Flag] values, alg constraints, and policy switches
// drawn from a published specification (FAPI, iGov, …).
//
// Profiles compose multiplicatively: enabling [FAPI2Baseline] is equivalent
// to enabling its underlying features and policies in one call. A profile
// MUST NOT be relaxed by a later option; the library rejects [op.New]
// configurations whose options would weaken an enabled profile.
package profile
