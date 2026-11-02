package tokenendpoint

import (
	"context"
	"errors"
	"net/http"
	"reflect"

	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/internal/grants/refresh"
	"github.com/libraz/go-oidc-provider/internal/oidcscope"
	"github.com/libraz/go-oidc-provider/op/store"
)

// requireRegisteredScopes re-applies the client's registered Scopes to a
// scope set the OP is about to issue against. Returns true when the
// request may proceed.
//
// The set was already a subset of the registration when the grant was
// created, so the only way this fails is that the registration was
// narrowed while the chain (or an unredeemed authorization code) was
// live — which is exactly the case it exists for. Without it, tightening
// a compromised client's Scopes stops /authorize, /device_authorization
// and client_credentials but leaves every running refresh chain minting
// access tokens at the original scope indefinitely, so containment would
// need the coarser step of revoking the grants.
//
// The check runs on both sides of the exchanger: before Consume, so a
// rejected rotation does not spend the presented token, and after it as
// defence in depth for the grace path, whose consumed record bypasses
// the preflight.
func requireRegisteredScopes(w http.ResponseWriter, client *store.Client, scope []string) bool {
	if client == nil || oidcscope.Subset(scope, client.Scopes) {
		return true
	}
	endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errInvalidScope,
		"scope exceeds the client's registered scopes")
	return false
}

// preflightRefreshBeforeConsume applies the refresh token's checks that must
// not spend it. On success it returns the record read, or nil when the token
// is unknown or already consumed so the exchanger owns replay and invalid_grant
// handling.
func preflightRefreshBeforeConsume(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	deps Deps,
	client *store.Client,
	in refreshInputs,
	dpopOut *dpopOutcome,
) (*store.RefreshToken, bool) {
	clientID := client.ID
	rec, err := deps.RefreshTokens.Find(ctx, in.Token)
	if err == nil && rec == nil {
		// A nil record alongside a nil error violates the store contract.
		// Treat it as a miss: the preflight has nothing to check against and
		// the exchanger below still refuses the token.
		err = store.ErrNotFound
	}
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, true
		}
		endpointsupport.WriteServerError(w)
		return nil, false
	}
	if rec.ConsumedAt != nil {
		return nil, true
	}
	if rec.ClientID != clientID {
		endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errInvalidGrant, "refresh token rejected")
		return nil, false
	}
	if !rec.ExpiresAt.IsZero() && deps.now().UTC().After(rec.ExpiresAt) {
		endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errInvalidGrant, "refresh token rejected")
		return nil, false
	}
	scope, ok := preflightRefreshScope(w, rec.Scope, in.RequestedScope)
	if !ok {
		return nil, false
	}
	if !checkTokenScopeAllowlist(w, deps, clientID, scope) {
		return nil, false
	}
	if !requireRegisteredScopes(w, client, scope) {
		return nil, false
	}
	if !enforceStrictOfflineAccess(w, deps, rec.Scope, rec.Origin) {
		return nil, false
	}
	if !preflightRefreshSenderConstraint(w, r, deps, rec, dpopOut) {
		return nil, false
	}
	return rec, true
}

// preflightRefreshSenderConstraint rejects a missing or mismatched proof
// before Exchange consumes the single-use record. The post-exchange checks
// remain as defence in depth and cover the grace path, whose consumed
// record intentionally bypasses this preflight.
func preflightRefreshSenderConstraint(
	w http.ResponseWriter,
	r *http.Request,
	deps Deps,
	rec *store.RefreshToken,
	dpopOut *dpopOutcome,
) bool {
	if !enforceDPoPRefreshBinding(w, deps, dpopOut, rec.DPoPJKT) {
		return false
	}
	if !requireMTLSMatch(w, r, deps, rec.MTLSCertThumbprint) {
		return false
	}
	// A request shape the deployment refuses (no proof or certificate where
	// sender-constrained tokens are required) must not spend the token.
	return enforceSenderConstraint(w, deps, tokenBinding{
		DPoPJKT:        dpopOut.JKT,
		MTLSThumbprint: rec.MTLSCertThumbprint,
	})
}

func preflightRefreshScope(w http.ResponseWriter, granted, requested []string) ([]string, bool) {
	if len(requested) == 0 {
		return append([]string(nil), granted...), true
	}
	allowed := make(map[string]struct{}, len(granted))
	for _, s := range granted {
		allowed[s] = struct{}{}
	}
	out := make([]string, 0, len(requested))
	for _, s := range requested {
		if _, ok := allowed[s]; !ok {
			endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errInvalidScope,
				"requested scope exceeds the original grant")
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

// preflightRefreshAuthorizationDetails resolves and narrows the RFC 9396
// authorization_details before Exchange consumes the predecessor refresh
// token. The chain's own snapshot is authoritative and its live own-consent
// grant only narrows it, so a Grant Management replace withdraws details
// while a later authorization on the same grant never adds any (see
// [chainAuthorizationDetails]). The caller performs this read before opening any write
// transaction and passes the resulting immutable selection through to
// issuance.
//
// The returned effective details are passed unchanged into issuance. A
// transactional path revalidates the selection after its Consume and rolls
// that transition back when the Grant changed; the non-transactional path has
// no cross-store rollback and therefore retains this preflight selection.
func preflightRefreshAuthorizationDetails(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	rec *store.RefreshToken,
	requested []map[string]any,
) ([]map[string]any, bool) {
	if rec == nil {
		// Unknown or consumed token: the exchanger owns invalid_grant, replay
		// detection and grace-window recovery, and none issues from these details.
		return nil, true
	}

	grant, err := chainGrant(ctx, deps, rec.Origin, rec.GrantID)
	if err != nil {
		endpointsupport.WriteServerError(w)
		return nil, false
	}
	granted := chainAuthorizationDetails(grant, rec.ClientID, rec.AuthorizationDetails, rec.AuthorizationRecorded)
	return reduceAuthorizationDetails(w, requested, granted)
}

// revalidateRefreshAuthorizationDetails closes the gap between the
// request-side preflight and the transactional Consume. The preflight must
// stay outside the transaction because a read before Consume can establish a
// stale SQLite WAL snapshot. Once Consume has performed the write, however,
// the transaction can safely read the authoritative Grant and verify that the
// effective details selected before BeginTx are still valid at the write's
// serialization point.
//
// The selection is recomputed with the preflight's rule against the grant
// as it stands now: for an explicit request, the requested subset must
// still be present; for an omitted request, the complete narrowed set must
// match the effective set selected before Consume. A mismatch is a 400 rejection,
// and the caller rolls the transaction back so the predecessor remains
// redeemable for a retry against the current Grant.
func revalidateRefreshAuthorizationDetails(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	exchanged *refresh.Exchanged,
	requested []map[string]any,
	effective []map[string]any,
) bool {
	if exchanged == nil || exchanged.InGrace || deps.Grants == nil || exchanged.GrantID == "" ||
		!grantIsOwnConsent(exchanged.Origin) {
		return true
	}
	grant, err := findGrant(ctx, deps, exchanged.GrantID)
	if err != nil {
		endpointsupport.WriteServerError(w)
		return false
	}
	granted := chainAuthorizationDetails(grant, exchanged.ClientID, exchanged.AuthorizationDetails, exchanged.AuthorizationRecorded)
	want, ok := reduceAuthorizationDetails(w, requested, granted)
	if !ok {
		return false
	}
	if !reflect.DeepEqual(want, effective) {
		endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errInvalidAuthzDetails,
			"authorization_details changed while refresh was in flight")
		return false
	}
	return true
}

// enforceStrictOfflineAccess rejects a refresh exchange when the
// strict-mode flag is set and the token's bound scope does not contain
// "offline_access". A first use is checked in
// [preflightRefreshBeforeConsume], before Consume, so a refused pre-flag
// token stays unconsumed and redeems again if the flag is lifted. Only
// the grace path, whose record is already consumed, relies on the
// post-exchange call. Returns true when the request may proceed.
func enforceStrictOfflineAccess(w http.ResponseWriter, deps Deps, scope []string, origin store.RefreshTokenOrigin) bool {
	if !deps.StrictOfflineAccess {
		return true
	}
	if origin == store.RefreshOriginCustomGrant {
		return true
	}
	if oidcscope.ContainsOfflineAccess(scope) {
		return true
	}
	endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errInvalidGrant,
		"refresh issued without offline_access; refresh disabled by current policy")
	return false
}
