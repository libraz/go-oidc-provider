package op

import "context"

// ACRPolicy decides what acr / amr claims the OP writes onto an issued
// id_token, given the LoginContext at grant time and the internal
// [AAL] the authentication ceremony achieved. The policy seam exists
// because OIDC Core 1.0 §3.1.2.1 leaves the satisfaction predicate to
// the OP: reference products diverge on whether any MFA event satisfies
// any acr_values entry (Auth0, Okta), require a configured per-acr
// table (Keycloak), or delegate the call wholesale to the embedder
// (panva). See ADR 0012 for the rationale and the spec ambiguity this
// interface resolves.
//
// The library default is [DefaultACRPolicy], which echoes the first
// requested acr_values entry whenever the ceremony reached at least
// [AAL1]. Embedders that need a stricter mapping (e.g. a NIST SP
// 800-63 binding) supply their own policy via [WithACRPolicy].
//
// Stable since v0.x (ADR 0012 implementation). The interface is
// experimental until v1.0; the parameter list MAY grow in a backward-
// compatible way (additive arguments) before SemVer freezes it.
type ACRPolicy interface {
	// Resolve returns the acr / amr / ok triple for the id_token. ok =
	// false instructs the issuer to omit the acr claim entirely; amr is
	// then governed by the per-factor RFC 8176 aggregation alone.
	// ok = true with a non-empty acr writes that string into the
	// id_token's "acr" claim. ok = true with a nil amr leaves the
	// per-factor aggregated amr in place; a non-nil amr replaces it.
	Resolve(ctx context.Context, lc LoginContext, internal AAL) (acr string, amr []string, ok bool)

	// Satisfies reports whether the supplied AAL plus completed-step
	// list is enough to claim the requested acr string. The default
	// implementation is the lax interpretation OFCS expects ("any
	// requested string is satisfied if internal >= AAL1"); strict
	// deployments override this to consult a configured per-acr table.
	Satisfies(ctx context.Context, requested string, internal AAL, completed []StepKind) bool
}

// DefaultACRPolicy is the library's reference [ACRPolicy]. It is the
// value [WithACRPolicy] installs when no policy is supplied:
//
//   - Resolve with an empty [LoginContext.ACRValues] returns the AAL's
//     canonical InCommon URI ([AAL.ACRURI]) so the wire shape matches
//     the pre-ADR-0012 default.
//   - Resolve with non-empty ACRValues returns the first entry for
//     which [DefaultACRPolicy.Satisfies] returns true, mirroring the
//     OIDC Core 1.0 §3.1.2.1 "echo a requested value when satisfied"
//     posture and the OFCS oidcc-ensure-request-with-acr-values-
//     succeeds expectation. When no entry is satisfiable the policy
//     returns ok=false and the issuer omits the acr claim.
//   - Satisfies treats every non-empty requested string as satisfied
//     once the ceremony reached [AAL1] or above. The interpretation is
//     intentionally lax: strict deployments install their own
//     [ACRPolicy] via [WithACRPolicy].
//
// Stable since v0.x (ADR 0012 implementation).
type DefaultACRPolicy struct{}

// Resolve implements [ACRPolicy].
func (DefaultACRPolicy) Resolve(ctx context.Context, lc LoginContext, internal AAL) (string, []string, bool) {
	if len(lc.ACRValues) == 0 {
		uri := internal.ACRURI()
		if uri == "" {
			return "", nil, false
		}
		return uri, nil, true
	}
	policy := DefaultACRPolicy{}
	for _, want := range lc.ACRValues {
		if policy.Satisfies(ctx, want, internal, lc.CompletedSteps) {
			return want, nil, true
		}
	}
	return "", nil, false
}

// Satisfies implements [ACRPolicy].
func (DefaultACRPolicy) Satisfies(_ context.Context, requested string, internal AAL, _ []StepKind) bool {
	if requested == "" {
		return false
	}
	return internal >= AAL1
}
