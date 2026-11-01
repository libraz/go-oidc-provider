package authorizeendpoint

import (
	"reflect"
	"slices"

	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/internal/oidcscope"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
)

// consentAlreadyCovered reports whether the cached grant fully covers
// what this request would ask the user to approve. It is the single
// predicate behind both consent gates: the dispatcher's needConsent
// flag and the pre-marking of the built-in consent interaction in
// [initialInteractionsRun]. Keeping one predicate is what stops the
// two from disagreeing — a request the matrix routes to a consent
// prompt must never arrive at the orchestrator with consent already
// marked as run, which would hand the RP a code without a ceremony.
//
// Coverage requires all of:
//
//   - The RP did not ask for re-consent (prompt=consent is the RP's
//     explicit override and is never satisfied by a cached grant).
//   - No Grant Management action: create / replace / merge each mutate
//     a specific grant, and the mutation plus its ownership check run
//     in upsertGrant on the interaction path.
//   - A grant exists whose scope set subsumes the requested scope.
//   - Every requested RFC 9396 authorization_details element is already
//     on that grant.
func consentAlreadyCovered(req *authorize.Request, existing *store.Grant) bool {
	if req == nil || existing == nil {
		return false
	}
	if slices.Contains(req.Prompt, interaction.PromptConsent) {
		return false
	}
	if req.GrantManagementAction != "" {
		return false
	}
	return oidcscope.Subset(req.Scope, existing.Scope) &&
		authorizationDetailsCovered(req.AuthorizationDetails, existing)
}

// authorizationDetailsCovered reports whether every requested RFC 9396
// authorization_details element is already present on the grant. A request
// that introduces a new element is therefore not covered and runs through
// the interaction path, which persists it onto the grant, rather than
// silent-minting a code against a grant whose details do not match — which
// would drop the requested detail from a code the RP believes carries it.
//
// The ceremony that routing reaches presents scopes only. Neither the
// built-in consent step nor [interaction.ConsentScopePromptData] has an
// element-level row, and the submission answers with approved_scopes, so
// the elements ride on the authorization request and are persisted
// verbatim regardless of what the user approves. Routing here buys a fresh
// ceremony and a fresh grant amendment, not a display of the element's
// terms. A deployment that must show those terms — a payment amount, a
// payee — renders them from the authorization request in its own
// [interaction.Driver].
func authorizationDetailsCovered(requested []map[string]any, grant *store.Grant) bool {
	if len(requested) == 0 {
		return true
	}
	if grant == nil {
		return false
	}
	for _, want := range requested {
		found := false
		for _, have := range grant.AuthorizationDetails {
			if reflect.DeepEqual(have, want) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
