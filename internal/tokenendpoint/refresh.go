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
	issueRefreshResponse(ctx, w, deps, client, exchanged, dpopOut.JKT)
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
		Store: deps.RefreshTokens,
		Clock: deps.clockFunc(),
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
// dpopJKT is the thumbprint to bind on the rotated tokens. The caller
// passes either the verified proof's thumbprint (when DPoP was
// presented) or the consumed record's bound thumbprint (when the
// presented refresh token was already DPoP-bound and the proof simply
// matched). Both cases collapse to the same value because
// [requireDPoPMatch] enforces the equivalence; passing it through
// keeps a single source of truth on the wire.
func issueRefreshResponse(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	client *store.Client,
	exchanged *refresh.Exchanged,
	dpopJKT string,
) {
	now := deps.now().UTC()
	authTime := lookupAuthTime(ctx, deps, exchanged.GrantID)
	accessToken, err := mintAccessToken(deps, exchanged.Subject, client.ID, exchanged.Scope, now, authTime, dpopJKT)
	if err != nil {
		writeError(w, http.StatusInternalServerError, errServerError, "")
		return
	}
	idToken, err := maybeMintRefreshIDToken(deps, refreshIDTokenInput{
		Subject:  exchanged.Subject,
		ClientID: client.ID,
		Scope:    exchanged.Scope,
		Now:      now,
		AuthTime: authTime,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, errServerError, "")
		return
	}
	rotated, err := rotateRefreshToken(ctx, deps, client.ID, exchanged, dpopJKT)
	if err != nil {
		writeError(w, http.StatusInternalServerError, errServerError, "")
		return
	}
	writeSuccess(w, successResponse{
		AccessToken:  accessToken,
		TokenType:    tokenType(dpopJKT),
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
}

// maybeMintRefreshIDToken signs an id_token only when the rotated grant
// carries the "openid" scope. The token omits at_hash / c_hash / nonce
// because no fresh authentication occurred (OIDC Core 1.0 §12 — the
// refresh-token id_token re-issues identity claims but does not bind a
// fresh access token to a fresh authorization code).
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
	}
	return tokens.SignIDToken(activeSigningKey(deps), claims)
}

// rotateRefreshToken mints the next-generation refresh token whose
// ParentID points at the just-consumed id. The library always rotates;
// returning the original token would defeat the §2.2.2 replay defence
// the exchanger already enforces. dpopJKT is propagated onto the
// rotated record so the binding survives across the chain (RFC 9449
// §6.1).
func rotateRefreshToken(
	ctx context.Context,
	deps Deps,
	clientID string,
	exchanged *refresh.Exchanged,
	dpopJKT string,
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
	return issuer.Issue(ctx, refresh.IssueInput{
		ClientID: clientID,
		Subject:  exchanged.Subject,
		GrantID:  exchanged.GrantID,
		Scope:    append([]string(nil), exchanged.Scope...),
		ParentID: &parent,
		DPoPJKT:  dpopJKT,
	})
}
