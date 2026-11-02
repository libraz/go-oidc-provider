package tokenendpoint

import (
	"context"
	"errors"
	"net/http"

	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/internal/grants/refresh"
	"github.com/libraz/go-oidc-provider/op/store"
)

// serveGraceRetry answers a refresh presented inside the rotation
// grace window (RFC 9700 §2.2.2), where the client is retrying an
// exchange whose response it never received. It replays the cached
// response rather than rotating again, so a lost response does not
// cost the client its chain. Every branch writes a response.
func serveGraceRetry(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	client *store.Client,
	exchanged *refresh.Exchanged,
	binding tokenBinding,
	transactional bool,
	rotation *rotationOutcome,
) {
	response, found, err := loadRefreshRetryResponse(ctx, deps, exchanged.ConsumedID)
	if err != nil {
		endpointsupport.WriteOAuthError(w, http.StatusInternalServerError, errServerError, "")
		return
	}
	if !found {
		// The rotation that consumed this token cached nothing to
		// replay, so there is no response to recover: an OP running
		// without retry-response encryption keys rotates without a
		// cache at all. The presented token is spent either way, so
		// the retry earns the same invalid_grant a presentation past
		// the grace window earns — indistinguishable on the wire, and
		// no chain revocation, because the successor is live and the
		// client has done nothing wrong.
		endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errInvalidGrant, "refresh token rejected")
		return
	}
	// A grace retry may not widen or otherwise change the effective scope
	// of the response originally cached for this predecessor.
	if response.Scope != joinScope(exchanged.Scope) {
		endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errInvalidGrant, "refresh token retry does not match original exchange")
		return
	}
	// Bearer chains recover the cached response verbatim (RFC 9700
	// §2.2.2). Sender-constrained chains cannot: RFC 9449 §5/§6 binds
	// each access token to the DPoP key (or mTLS certificate) the
	// request presents, and a confidential client may rotate that key
	// across refreshes — replaying the originally-bound token would
	// hand back one the client can no longer use. Re-mint the access
	// token against the current binding while keeping the idempotent
	// successor refresh token and id_token.
	//
	// The bearer branch below mints nothing, so it leaves the single live
	// access token the original rotation produced exactly as it is; the
	// re-minting branch owes the prior-token cascade.
	if binding.constrained() {
		reissueGraceAccessToken(ctx, w, deps, client, exchanged, binding, &response, transactional, rotation)
		return
	}
	writeSuccess(w, response)
}

// reissueGraceAccessToken re-binds the access token of an RFC 9700 §2.2.2
// grace replay to the sender-constraint the *current* request presents,
// then re-emits the original rotation's idempotent remainder (successor
// refresh token, id_token, scope, authorization_details, grant_id) from
// the cached response.
//
// RFC 9700 grace recovery must return the same successor refresh token so
// a client that lost the original response is not locked out — the chain
// is never rotated again. RFC 9449 §5/§6, however, binds every issued
// access token to the DPoP key (or, for mTLS, the client certificate)
// presented on the request that produced it, and a confidential client
// is free to rotate that DPoP key across refreshes. Replaying the
// originally-minted access token verbatim would therefore hand back a
// token bound to a key the client may no longer hold, so every resource
// call would fail with an invalid_token thumbprint mismatch. The refresh
// token stays fixed; only the access token is minted afresh against the
// current binding, and the guards a first-issue refresh runs before its
// mint run here too: the grant-closure refusal, so a replay cannot
// slip a fresh access token past a grant that has since been revoked, and
// the prior-opaque-access-token cascade, so the retry does not leave the
// access token from the original rotation live alongside the one it hands
// back. Both are re-runs of idempotent work — the cascade revokes by chain
// and the tombstone check only reads — so recovering a lost response costs
// the client nothing extra.
func reissueGraceAccessToken(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	client *store.Client,
	exchanged *refresh.Exchanged,
	binding tokenBinding,
	response *successResponse,
	transactional bool,
	rotation *rotationOutcome,
) {
	if !refuseIssuanceUnderClosedGrant(ctx, w, deps, refreshIssuedUnderGrant(exchanged), "refresh token rejected") {
		return
	}
	if !retirePriorOpaqueAccessTokens(ctx, w, deps, client, exchanged, transactional) {
		return
	}
	now := deps.now().UTC()
	authCtx, err := refreshAuthContext(ctx, deps, exchanged)
	if err != nil {
		endpointsupport.WriteOAuthError(w, http.StatusInternalServerError, errServerError, "")
		return
	}
	accessToken, _, err := mintRefreshAccessToken(ctx, deps, client, exchanged, authCtx, binding, response.AuthorizationDetails, now)
	if err != nil {
		endpointsupport.WriteOAuthError(w, http.StatusInternalServerError, errServerError, "")
		return
	}
	response.AccessToken = accessToken
	response.TokenType = binding.tokenTypeFor()
	response.ExpiresIn = int64(deps.AccessTokenTTL.Seconds())
	issued := refreshIssuedUnderGrant(exchanged)
	issued.AccessToken = accessToken
	rotation.recordIssued(issued)
	writeSuccess(w, *response)
}

// loadRefreshRetryResponse recovers the response cached for predecessor
// by the rotation that consumed it. found reports whether a cached
// response exists at all; an error is reserved for a lookup that should
// have succeeded.
//
// The absent cases are legitimate configurations rather than faults.
// Retry responses are sealed with the cookie keys, which are mandatory
// only for the authorization-code grant, so a deployment built around
// CIBA, the device flow, or a custom grant can run without them; that
// deployment's rotations never cache anything, and neither does an
// entry whose retention has lapsed. Both surface as found=false so the
// caller can answer the retry rather than fail it.
func loadRefreshRetryResponse(
	ctx context.Context,
	deps Deps,
	predecessor string,
) (response successResponse, found bool, err error) {
	if len(deps.RefreshRetryEncryptionKeys) == 0 {
		return successResponse{}, false, nil
	}
	retries, ok := deps.RefreshTokens.(store.RefreshRetryResponseStore)
	if !ok {
		return successResponse{}, false,
			errors.New("tokenendpoint: refresh store does not support durable retry responses")
	}
	sealed, err := retries.LoadRetryResponse(ctx, predecessor)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return successResponse{}, false, nil
		}
		return successResponse{}, false, err
	}
	response, err = openRefreshRetryResponse(deps.RefreshRetryEncryptionKeys, predecessor, sealed)
	if err != nil {
		return successResponse{}, false, err
	}
	return response, true, nil
}
