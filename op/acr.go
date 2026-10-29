package op

import (
	"context"

	"github.com/libraz/go-oidc-provider/internal/authn"
)

// ACRPolicy decides what acr / amr claims the OP writes onto an issued
// id_token, given the LoginContext at grant time and the internal
// [AAL] the authentication ceremony achieved. The policy seam exists
// because OIDC Core 1.0 §3.1.2.1 leaves the satisfaction predicate to
// the OP. Deployed providers land in three places: any MFA event
// satisfies any acr_values entry, a configured per-acr table decides,
// or the call is delegated wholesale to the embedder. The library
// default is the per-acr table ([ACRLevels]); the seam lets an embedder
// replace it wholesale.
//
// Resolve runs for every response, including one served from an
// existing session without a new ceremony. There internal is the level
// the session recorded, [LoginContext.CompletedSteps] is empty, and the
// verdict is for the requesting client alone: a session records the
// canonical acr of the level it reached ([AAL.ACRURI]), never an acr an
// earlier request drew from the policy.
//
// The library default is [DefaultACRPolicy], which writes only an acr
// the ceremony actually satisfied. Embedders that need a different
// mapping (e.g. a NIST SP 800-63 binding) supply their own policy via
// [WithACRPolicy].
//
// Stable since v1.0.
type ACRPolicy interface {
	// Resolve returns the acr / amr / ok triple for the id_token.
	// ok = true with a non-empty acr writes that string into the
	// id_token's "acr" claim. ok = true with a nil amr leaves the
	// per-factor aggregated amr in place; a non-nil amr replaces it.
	//
	// ok = false means the policy could not satisfy the request. The wire
	// layer then refuses an essential acr request with
	// unmet_authentication_requirements; for a voluntary request it
	// writes the canonical acr the session recorded (the level actually
	// reached, none at [AAL0]). amr is governed by the per-factor RFC
	// 8176 aggregation alone.
	Resolve(ctx context.Context, lc LoginContext, internal AAL) (acr string, amr []string, ok bool)

	// Satisfies reports whether the supplied AAL plus completed-step
	// list is enough to claim the requested acr string. The default
	// implementation consults a per-acr level table ([ACRLevels]);
	// deployments with other rules override it.
	Satisfies(ctx context.Context, requested string, internal AAL, completed []StepKind) bool
}

// ACRLevels maps an acr string to the minimum [AAL] that satisfies it.
// It implements [ACRPolicy] and is how an embedder declares custom acr
// values for [WithACRPolicy]:
//
//	op.WithACRPolicy(op.ACRLevels{"urn:example:mfa": op.AAL2})
//
// A requested acr is looked up in the map first, then among the
// canonical URIs ([AAL1], [AAL2], [AAL3] via [AAL.ACRURI]); it is
// satisfied when the level found is at most the level the ceremony
// reached. A value found in neither is never satisfied. A nil or empty
// map recognises the canonical URIs only.
//
// Keys must be non-empty, values must be [AAL1] through [AAL3], and a
// key equal to a canonical URI must carry that URI's own level;
// [New] rejects anything else. Do not mutate the map after passing it
// to [New].
//
// Resolve without requested values returns the canonical URI of the
// reached level (none at [AAL0]). With requested values it returns the
// first one satisfied, or ok = false when none is.
//
// Stable since v1.5.
type ACRLevels map[string]AAL

// level returns the level requested names: the map entry, else the
// canonical URI's level. ok is false for an unknown value or one mapped
// outside [AAL1]..[AAL3].
func (m ACRLevels) level(requested string) (AAL, bool) {
	if requested == "" {
		return AAL0, false
	}
	lvl, found := m[requested]
	if !found {
		lvl = authn.AALFromACRURI(requested)
	}
	if lvl < AAL1 || lvl > AAL3 {
		return AAL0, false
	}
	return lvl, true
}

// Resolve implements [ACRPolicy].
func (m ACRLevels) Resolve(ctx context.Context, lc LoginContext, internal AAL) (string, []string, bool) {
	if len(lc.ACRValues) == 0 {
		uri := internal.ACRURI()
		if uri == "" {
			return "", nil, false
		}
		return uri, nil, true
	}
	for _, want := range lc.ACRValues {
		if m.Satisfies(ctx, want, internal, lc.CompletedSteps) {
			return want, nil, true
		}
	}
	return "", nil, false
}

// Satisfies implements [ACRPolicy].
func (m ACRLevels) Satisfies(_ context.Context, requested string, internal AAL, _ []StepKind) bool {
	lvl, ok := m.level(requested)
	return ok && lvl <= internal
}

// DefaultACRPolicy is the library's reference [ACRPolicy]. It is the
// value [WithACRPolicy] installs when no policy is supplied, and behaves
// as an [ACRLevels] with no custom entries:
//
//   - Resolve with an empty [LoginContext.ACRValues] returns the AAL's
//     canonical InCommon URI ([AAL.ACRURI]).
//   - Resolve with non-empty ACRValues returns the first entry the
//     ceremony satisfied; when none is, it returns ok=false and the
//     wire layer refuses an essential request or reports the level
//     actually reached for a voluntary one.
//   - Satisfies accepts a requested value only when it is a canonical
//     URI whose level the ceremony reached. Unknown values are never
//     satisfied; declare custom acr values with [ACRLevels].
//
// Stable since v1.0.
type DefaultACRPolicy struct{}

// Resolve implements [ACRPolicy].
func (DefaultACRPolicy) Resolve(ctx context.Context, lc LoginContext, internal AAL) (string, []string, bool) {
	return ACRLevels(nil).Resolve(ctx, lc, internal)
}

// Satisfies implements [ACRPolicy].
func (DefaultACRPolicy) Satisfies(ctx context.Context, requested string, internal AAL, completed []StepKind) bool {
	return ACRLevels(nil).Satisfies(ctx, requested, internal, completed)
}
