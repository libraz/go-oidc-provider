package tokenendpoint

import (
	"context"

	"github.com/libraz/go-oidc-provider/internal/grants/refresh"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
)

// grantIsOwnConsent reports whether a chain's GrantID names the requesting
// client's own consent record. A custom-grant chain's GrantID is backed by
// no record, or — for token exchange — by the subject_token's grant: another
// client's consent, which the chain joins for revocation and subject
// liveness only, never as a source of per-authorization state.
func grantIsOwnConsent(origin store.RefreshTokenOrigin) bool {
	return origin != store.RefreshOriginCustomGrant
}

// withChainID returns exchanged with a chain to record on the successor and
// on the access token minted alongside. A chain written before chains were
// recorded is given one here, so its rotations retire by chain from the
// next one on.
func withChainID(exchanged *refresh.Exchanged) (*refresh.Exchanged, error) {
	if exchanged.ChainID != "" {
		return exchanged, nil
	}
	chainID, err := refresh.NewChainID()
	if err != nil {
		return nil, err
	}
	out := *exchanged
	out.ChainID = chainID
	return &out, nil
}

// refreshExchangedForRotation stamps the successor with the
// per-authorization state this rotation resolved, so a chain written before
// the state was recorded stops consulting its grant from here on.
func refreshExchangedForRotation(exchanged *refresh.Exchanged, authCtx authContext, details []map[string]any) *refresh.Exchanged {
	if exchanged == nil {
		return nil
	}
	out := *exchanged
	out.AuthTime = timeFromUnix(authCtx.AuthTime)
	out.ACR = authCtx.ACR
	out.AMR = append([]string(nil), authCtx.AMR...)
	out.AuthorizationDetails = cloneAuthorizationDetails(details)
	out.Claims = cloneClaimsMap(authCtx.EncodedClaims)
	out.AuthorizationRecorded = true
	return &out
}

// refreshAuthContext resolves the per-authorization state of the chain the
// consumed token belongs to: what the chain recorded at its root, with
// its own-consent grant only narrowing authorization_details or standing
// in for a row written without the state. A grant that cannot be read is
// an error rather than a skipped narrowing.
func refreshAuthContext(ctx context.Context, deps Deps, exchanged *refresh.Exchanged) (authContext, error) {
	own := tokens.Authorization{
		AuthTime:             exchanged.AuthTime,
		ACR:                  exchanged.ACR,
		AMR:                  exchanged.AMR,
		AuthorizationDetails: exchanged.AuthorizationDetails,
		Claims:               exchanged.Claims,
	}
	g, err := chainGrant(ctx, deps, exchanged.Origin, exchanged.GrantID)
	if err != nil {
		return authContext{}, err
	}
	return authContextOf(deps, tokens.ResolveAuthorization(own, exchanged.AuthorizationRecorded, g, exchanged.ClientID)), nil
}

// chainAuthorizationDetails is the authorization_details a chain may still
// issue: its own snapshot narrowed by its live grant, per
// [tokens.ResolveAuthorization].
func chainAuthorizationDetails(g *store.Grant, clientID string, snapshot []map[string]any, recorded bool) []map[string]any {
	own := tokens.Authorization{AuthorizationDetails: cloneAuthorizationDetails(snapshot)}
	return tokens.ResolveAuthorization(own, recorded, g, clientID).AuthorizationDetails
}

// chainGrant returns the grant a chain may consult: its own consent, never
// the grant a custom-grant chain descends from. A lookup fault is returned,
// per [findGrant].
func chainGrant(ctx context.Context, deps Deps, origin store.RefreshTokenOrigin, grantID string) (*store.Grant, error) {
	if !grantIsOwnConsent(origin) {
		return nil, nil //nolint:nilnil // the chain has no own-consent grant
	}
	return findGrant(ctx, deps, grantID)
}

// chainGrantIDForResponse is [grantIDForResponse] for a rotation: only a
// chain rooted on the client's own consent names a grant that client can
// address at the grant management endpoint.
func chainGrantIDForResponse(deps Deps, exchanged *refresh.Exchanged) string {
	if !grantIsOwnConsent(exchanged.Origin) {
		return ""
	}
	return grantIDForResponse(deps, exchanged.GrantID)
}
