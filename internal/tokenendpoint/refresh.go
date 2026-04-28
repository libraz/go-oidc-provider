package tokenendpoint

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/internal/grants/refresh"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
)

// handleRefreshToken implements the "grant_type=refresh_token" branch of
// RFC 6749 §6 and the rotation contract of RFC 9700 §2.2.2. The function
// orchestrates client authentication, refresh-token exchange (which
// consumes the presented token), id_token re-issuance for OIDC grants,
// and rotation (which mints a new refresh token whose ParentID points
// at the just-consumed one).
//
// When the consumed refresh token was DPoP-bound the rotation path
// requires a matching proof on the request and re-binds the issued
// access / refresh tokens to the same thumbprint (RFC 9449 §5.2).
// When the consumed refresh token was mTLS-bound the path additionally
// requires a client cert whose RFC 8705 §3.1 thumbprint matches the
// stored value; mTLS bindings are NOT auto-upgraded mid-chain (unlike
// DPoP, which RFC 9449 §5.2 allows to bind opportunistically on
// first refresh).
func handleRefreshToken(w http.ResponseWriter, r *http.Request, deps Deps) {
	ctx := r.Context()
	client, _, ok := authenticate(ctx, w, r, deps)
	if !ok {
		return
	}
	in, ok := parseRefreshRequest(w, r)
	if !ok {
		return
	}
	if !checkRefreshScopeAllowlist(w, deps, client.ID, in.RequestedScope) {
		return
	}
	exchanged, ok := exchangeRefresh(ctx, w, deps, client.ID, in)
	if !ok {
		return
	}
	dpopOut, ok := requireDPoPMatch(w, r, deps, exchanged.DPoPJKT)
	if !ok {
		return
	}
	if !requireMTLSMatch(w, r, deps, exchanged.MTLSCertThumbprint) {
		return
	}
	binding := tokenBinding{
		DPoPJKT:        dpopOut.JKT,
		MTLSThumbprint: exchanged.MTLSCertThumbprint,
	}
	if !enforceSenderConstraint(w, deps, binding) {
		return
	}
	issueRefreshResponse(ctx, w, deps, client, exchanged, binding)
}

// checkRefreshScopeAllowlist enforces the per-scope AllowedClients
// allowlist for any scope the RP explicitly requested at /token. The
// check runs before [refresh.Exchanger.Exchange] so an allowlist
// violation does not consume the presented refresh token. An empty
// requested-scope list bypasses the check; the rotated token reuses
// the bound scope, which was already validated when the originating
// authorization code was issued.
func checkRefreshScopeAllowlist(
	w http.ResponseWriter,
	deps Deps,
	clientID string,
	requested []string,
) bool {
	if deps.Scopes == nil || len(requested) == 0 {
		return true
	}
	for _, s := range requested {
		if !deps.Scopes.Allows(s, clientID) {
			writeError(w, http.StatusBadRequest, errInvalidScope,
				"scope is restricted to a different client")
			return false
		}
	}
	return true
}

// refreshInputs is the de-structured view of the form parameters the
// handler consumes for the refresh_token grant.
type refreshInputs struct {
	Token          string
	RequestedScope []string
}

// parseRefreshRequest validates the required form fields. The "scope"
// parameter is optional; an empty value means "use the bound scope".
func parseRefreshRequest(w http.ResponseWriter, r *http.Request) (refreshInputs, bool) {
	in := refreshInputs{
		Token:          r.PostForm.Get("refresh_token"),
		RequestedScope: parseScopeParam(r.PostForm.Get("scope")),
	}
	if in.Token == "" {
		writeError(w, http.StatusBadRequest, errInvalidRequest, "refresh_token is required")
		return refreshInputs{}, false
	}
	return in, true
}

// parseScopeParam splits the canonical RFC 6749 §3.3 space-delimited
// scope string. Empty strings yield a nil slice so callers can treat
// "scope absent" identically to "scope empty".
func parseScopeParam(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, " ")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// exchangeRefresh runs the [refresh.Exchanger] and translates sentinel
// errors into the wire form. Returns ok=false when a response has
// already been written.
func exchangeRefresh(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	clientID string,
	in refreshInputs,
) (*refresh.Exchanged, bool) {
	exchanger, err := refresh.NewExchanger(refresh.ExchangerConfig{
		Store:    deps.RefreshTokens,
		Clock:    deps.clockFunc(),
		GraceTTL: deps.RefreshTokenGraceTTL,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, errServerError, "")
		return nil, false
	}
	exchanged, err := exchanger.Exchange(ctx, refresh.ExchangeInput{
		Token:          in.Token,
		ClientID:       clientID,
		RequestedScope: in.RequestedScope,
	})
	if err != nil {
		writeRefreshExchangeError(w, err)
		return nil, false
	}
	return exchanged, true
}

// writeRefreshExchangeError maps the refresh-package sentinels onto wire
// codes. Replay handling lives entirely inside [refresh.Exchanger]
// (which calls RevokeChain before returning ErrTokenReplayed), so the
// HTTP layer only has to surface the right wire code.
func writeRefreshExchangeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, refresh.ErrTokenMissing),
		errors.Is(err, refresh.ErrTokenExpired),
		errors.Is(err, refresh.ErrTokenReplayed),
		errors.Is(err, refresh.ErrClientMismatch):
		writeError(w, http.StatusBadRequest, errInvalidGrant, "refresh token rejected")
	case errors.Is(err, refresh.ErrScopeWidening):
		writeError(w, http.StatusBadRequest, errInvalidScope,
			"requested scope exceeds the original grant")
	default:
		writeError(w, http.StatusInternalServerError, errServerError, "")
	}
}

// issueRefreshResponse mints the access token, optionally an id_token
// (only when the originating grant carried "openid"), and rotates the
// refresh token (mints a fresh one whose ParentID is the just-consumed
// id). Failure on any step writes a 500 because the exchange has
// already committed; we cannot un-consume the presented token.
//
// binding is the sender-constraint summary the rotated tokens inherit.
// For DPoP it is either the verified proof's thumbprint (request
// presented a proof) or the consumed record's bound thumbprint
// (chain was already bound and the proof simply matched); for mTLS
// it is always the consumed record's thumbprint (mTLS does not
// admit mid-chain upgrades). Both cases collapse to a single source
// of truth on the wire and on the persisted rotated record.
func issueRefreshResponse(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	client *store.Client,
	exchanged *refresh.Exchanged,
	binding tokenBinding,
) {
	now := deps.now().UTC()
	authCtx := lookupAuthContext(ctx, deps, exchanged.GrantID)
	accessToken, err := mintAccessToken(deps, exchanged.Subject, client.ID, exchanged.Scope, now, authCtx.AuthTime, binding)
	if err != nil {
		writeError(w, http.StatusInternalServerError, errServerError, "")
		return
	}
	idToken, err := maybeMintRefreshIDToken(deps, refreshIDTokenInput{
		Subject:  exchanged.Subject,
		ClientID: client.ID,
		Scope:    exchanged.Scope,
		Now:      now,
		AuthTime: authCtx.AuthTime,
		ACR:      authCtx.ACR,
		AMR:      authCtx.AMR,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, errServerError, "")
		return
	}
	var rotated string
	if !exchanged.InGrace {
		rotated, err = rotateRefreshToken(ctx, deps, client, exchanged, binding)
		if err != nil {
			writeError(w, http.StatusInternalServerError, errServerError, "")
			return
		}
	}
	writeSuccess(w, successResponse{
		AccessToken:  accessToken,
		TokenType:    binding.tokenTypeFor(),
		ExpiresIn:    int64(deps.AccessTokenTTL.Seconds()),
		RefreshToken: rotated,
		IDToken:      idToken,
		Scope:        joinScope(exchanged.Scope),
	})
}

// refreshIDTokenInput collects the parameters
// [maybeMintRefreshIDToken] needs. It mirrors [mintIDTokenInput] but
// omits the at_hash / c_hash / nonce fields the refresh path does not
// populate.
type refreshIDTokenInput struct {
	Subject  string
	ClientID string
	Scope    []string
	Now      time.Time
	AuthTime int64
	ACR      string
	AMR      []string
}

// maybeMintRefreshIDToken signs an id_token only when the rotated grant
// carries the "openid" scope. The token omits at_hash / c_hash / nonce
// because no fresh authentication occurred (OIDC Core 1.0 §12 — the
// refresh-token id_token re-issues identity claims but does not bind a
// fresh access token to a fresh authorization code). acr / amr are
// copied from the originating authentication so the spec's "same as
// the original ID Token" requirement holds across rotations.
func maybeMintRefreshIDToken(deps Deps, in refreshIDTokenInput) (string, error) {
	if !scopeContainsOpenID(in.Scope) {
		return "", nil
	}
	claims := tokens.IDTokenClaims{
		Issuer:    deps.Issuer,
		Subject:   in.Subject,
		Audience:  []string{in.ClientID},
		IssuedAt:  in.Now.Unix(),
		ExpiresAt: tokens.ExpiresIn(in.Now, deps.IDTokenTTL),
		AuthTime:  in.AuthTime,
		ACR:       in.ACR,
		AMR:       append([]string(nil), in.AMR...),
	}
	return tokens.SignIDToken(activeSigningKey(deps), claims)
}

// rotateRefreshToken mints the next-generation refresh token whose
// ParentID points at the just-consumed id. The library always rotates;
// returning the original token would defeat the §2.2.2 replay defence
// the exchanger already enforces. The binding is propagated onto the
// rotated record so the sender constraint (RFC 9449 §6.1 for DPoP,
// RFC 8705 §3.1 for mTLS) survives across the chain.
//
// DPoP rules per RFC 9449 §5.4: once the AS has bound a refresh token
// to a DPoP key the binding MUST persist across rotations. The
// "no-bind for confidential clients" policy therefore applies only
// when the consumed chain was NOT already bound: an opportunistic
// upgrade on the first refresh would lock subsequent refreshes to a
// single key, which contradicts the RFC 9449 §5 guidance for
// confidential clients.
func rotateRefreshToken(
	ctx context.Context,
	deps Deps,
	client *store.Client,
	exchanged *refresh.Exchanged,
	binding tokenBinding,
) (string, error) {
	issuer, err := refresh.NewIssuer(refresh.IssuerConfig{
		Store: deps.RefreshTokens,
		Clock: deps.clockFunc(),
		TTL:   deps.RefreshTokenTTL,
	})
	if err != nil {
		return "", err
	}
	parent := exchanged.ConsumedID
	rotatedJKT := binding.DPoPJKT
	if exchanged.DPoPJKT == "" {
		// Chain was not previously bound: apply the issuance-time
		// policy (public clients bind, confidential clients leave
		// empty). When the chain is already bound, exchanged.DPoPJKT
		// equals binding.DPoPJKT (requireDPoPMatch enforced match)
		// and we keep that value so the chain stays bound.
		rotatedJKT = refreshDPoPJKT(client, binding.DPoPJKT)
	}
	return issuer.Issue(ctx, refresh.IssueInput{
		ClientID:           client.ID,
		Subject:            exchanged.Subject,
		GrantID:            exchanged.GrantID,
		Scope:              append([]string(nil), exchanged.Scope...),
		ParentID:           &parent,
		DPoPJKT:            rotatedJKT,
		MTLSCertThumbprint: binding.MTLSThumbprint,
	})
}
