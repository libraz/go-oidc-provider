package tokenendpoint

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/grants/refresh"
	"github.com/libraz/go-oidc-provider/internal/oidcscope"
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
	// DPoP verification runs ahead of client authentication so the
	// `use_dpop_nonce` challenge fires before any client_assertion jti
	// is consumed. The bound-chain invariants (proof required when the
	// presented refresh token was DPoP-bound, jkt match) depend on the
	// exchange outcome and are enforced post-exchange via
	// [enforceDPoPRefreshBinding]. Mirrors handleAuthorizationCode.
	dpopOut, ok := verifyTokenDPoP(w, r, deps)
	if !ok {
		return
	}
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
	if !checkTokenScopeAllowlist(w, deps, client.ID, exchanged.Scope) {
		return
	}
	if !enforceStrictOfflineAccess(w, deps, exchanged.Scope) {
		return
	}
	if !enforceDPoPRefreshBinding(w, deps, dpopOut, exchanged.DPoPJKT) {
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
		RequestedScope: oidcscope.Parse(r.PostForm.Get("scope")),
	}
	if in.Token == "" {
		writeError(w, http.StatusBadRequest, errInvalidRequest, "refresh_token is required")
		return refreshInputs{}, false
	}
	return in, true
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
		Store:             deps.RefreshTokens,
		Clock:             deps.clockFunc(),
		GraceTTL:          deps.RefreshTokenGraceTTL,
		Audit:             deps.audit(),
		GrantRevocations:  refreshChainRevocationStore(deps),
		GrantTombstoneTTL: refreshChainTombstoneTTL(deps),
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

// enforceStrictOfflineAccess rejects a refresh exchange when the
// strict-mode flag is set and the consumed token's bound scope does
// not contain "offline_access". The check runs after the exchanger
// has already consumed the token, so the rejection is single-shot:
// embedders flipping [op.WithStrictOfflineAccess] on a live
// deployment must accept that pre-flag refresh tokens are
// invalidated on first use, which matches the ADR's "rejected on
// first use" stance. Returns true when the request may proceed.
func enforceStrictOfflineAccess(w http.ResponseWriter, deps Deps, scope []string) bool {
	if !deps.StrictOfflineAccess {
		return true
	}
	if oidcscope.ContainsOfflineAccess(scope) {
		return true
	}
	writeError(w, http.StatusBadRequest, errInvalidGrant,
		"refresh issued without offline_access; refresh disabled by current policy")
	return false
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
	if err := requireAuthTimeForIDToken(client, exchanged.Scope, authCtx.AuthTime); err != nil {
		writeError(w, http.StatusInternalServerError, errServerError, "required auth_time is unavailable")
		return
	}
	// Opaque-format chains revoke the prior access token atomically
	// with the new mint (ADR 0024 §"Refresh-rotation revocation of
	// prior AT"). Resource servers calling /oidc/introspect on every
	// request observe the revocation immediately, so the
	// stolen-but-still-valid window collapses to clock-skew. The JWT
	// path deliberately leaves prior tokens alive: doing otherwise
	// would force every JWT verification through introspection,
	// defeating the JWT optimisation that motivated the registry
	// design (ADR 0013). Revocation runs BEFORE the new mint so a
	// colliding hash on Save (impossible-by-construction with 256-bit
	// entropy) cannot leave the chain in a half-revoked state.
	revokePriorOpaqueAT(ctx, deps, exchanged.Resource, exchanged.GrantID)
	// ADR 0025 §"Mint refusal under tombstoned grant": under the
	// grant-tombstone strategy, refuse to mint a fresh access token
	// when the underlying grant has already been tombstoned. Without
	// this check a refresh racing a /end_session or code-replay
	// cascade could slip a fresh AT through ahead of the tombstone's
	// observable effect on resource-server lookups. The check
	// surfaces as invalid_grant per RFC 6749 §5.2 because the grant
	// was legitimately revoked, the refresh token is no longer
	// usable, and the failure is a property of the grant rather than
	// of the request shape.
	if !enforceGrantTombstoneMintRefusal(ctx, w, deps, exchanged) {
		return
	}
	publicSubject, err := projectPublicSubject(ctx, deps, exchanged.Subject, client)
	if err != nil {
		writeError(w, http.StatusInternalServerError, errServerError, "")
		return
	}
	accessToken, err := mintAccessToken(
		ctx,
		deps,
		exchanged.Subject,
		publicSubject,
		client.ID,
		exchanged.GrantID,
		exchanged.Scope,
		exchanged.Resource,
		now,
		authCtx.AuthTime,
		binding,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, errServerError, "")
		return
	}
	idTokenExtra := projectIDTokenClaims(ctx, deps, exchanged.Subject, authCtx.Claims)
	idToken, err := maybeMintRefreshIDToken(deps, refreshIDTokenInput{
		Subject:  publicSubject,
		ClientID: client.ID,
		Scope:    exchanged.Scope,
		Now:      now,
		AuthTime: authCtx.AuthTime,
		ACR:      authCtx.ACR,
		AMR:      authCtx.AMR,
		Nonce:    exchanged.Nonce,
		Extra:    idTokenExtra,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, errServerError, "")
		return
	}
	if idToken != "" {
		idToken, err = maybeEncryptIDToken(ctx, deps, client, idToken)
		if err != nil {
			writeError(w, http.StatusInternalServerError, errServerError, "")
			return
		}
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
// omits the at_hash / c_hash fields the refresh path does not populate.
type refreshIDTokenInput struct {
	Subject  string
	ClientID string
	Scope    []string
	Now      time.Time
	AuthTime int64
	ACR      string
	AMR      []string

	// Nonce is the OIDC Core 1.0 §3.1.2.1 nonce captured at the
	// originating authorization request, threaded through the
	// persisted refresh-token chain. OIDC Core §12 requires the
	// rotated id_token to preserve it.
	Nonce string

	// Extra carries the OIDC Core 1.0 §5.5 "claims"-projected
	// id_token claims resolved from the originating grant. nil when
	// the grant carried no §5.5 payload or the projector returned
	// no values.
	Extra map[string]any
}

// maybeMintRefreshIDToken signs an id_token only when the rotated grant
// carries the "openid" scope. The token omits at_hash / c_hash because
// the refresh-token id_token does not bind a fresh access token to a
// fresh authorization code, but it DOES carry the original nonce per
// OIDC Core 1.0 §12 ("if a nonce value was sent in the Authentication
// Request, a nonce Claim MUST be present"). acr / amr are copied from
// the originating authentication so the spec's "same as the original
// ID Token" requirement holds across rotations.
func maybeMintRefreshIDToken(deps Deps, in refreshIDTokenInput) (string, error) {
	if !oidcscope.ContainsOpenID(in.Scope) {
		return "", nil
	}
	claims := tokens.IDTokenClaims{
		Issuer:    deps.Issuer,
		Subject:   in.Subject,
		Audience:  []string{in.ClientID},
		IssuedAt:  in.Now.Unix(),
		ExpiresAt: tokens.ExpiresIn(in.Now, deps.IDTokenTTL),
		AuthTime:  in.AuthTime,
		Nonce:     in.Nonce,
		ACR:       in.ACR,
		AMR:       append([]string(nil), in.AMR...),
		Extra:     in.Extra,
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
		TTL:   pickRefreshTokenTTL(deps, exchanged.Scope),
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
		// equals binding.DPoPJKT (enforceDPoPRefreshBinding enforced
		// match) and we keep that value so the chain stays bound.
		rotatedJKT = refreshDPoPJKT(client, binding.DPoPJKT)
	}
	token, err := issuer.Issue(ctx, refresh.IssueInput{
		ClientID:           client.ID,
		Subject:            exchanged.Subject,
		GrantID:            exchanged.GrantID,
		Scope:              append([]string(nil), exchanged.Scope...),
		Resource:           exchanged.Resource,
		ParentID:           &parent,
		DPoPJKT:            rotatedJKT,
		MTLSCertThumbprint: binding.MTLSThumbprint,
		Nonce:              exchanged.Nonce,
	})
	if err != nil {
		return "", err
	}
	deps.audit().Emit(ctx, audit.Event{
		Name:     auditTokenRefreshed,
		Level:    audit.LevelInfo,
		Message:  "refresh token rotated",
		ActorID:  exchanged.Subject,
		ClientID: client.ID,
		Extras: map[string]any{
			"grant_id":       exchanged.GrantID,
			"offline_access": oidcscope.ContainsOfflineAccess(exchanged.Scope),
			"ttl_bucket":     ttlBucketFor(deps, exchanged.Scope),
		},
	})
	return token, nil
}

// enforceGrantTombstoneMintRefusal implements the ADR 0025 mint-
// refusal check on the refresh path: under
// [store.RevocationStrategyGrantTombstone] the OP refuses to sign a
// fresh access token when the underlying grant has already been
// tombstoned. The lookup uses the consumed refresh token's
// IssuedAt (its [store.RefreshToken.CreatedAt]) so the verifier's
// "iat <= RevokedAt" rule is honoured: a chain that was minted
// strictly before the tombstone is rejected even if the wall-clock
// race produced an iat of "RevokedAt".
//
// The function is a no-op when:
//
//   - The strategy is not [store.RevocationStrategyGrantTombstone].
//     [store.RevocationStrategyJTIRegistry] preserves the ADR 0013
//     behaviour where the next refresh attempt is blocked by the RT
//     cascade hitting the chain root, not by a per-mint check.
//     [store.RevocationStrategyNone] disables server-side JWT
//     revocation entirely.
//   - The substore is unwired (nil [Deps.GrantRevocations]). The
//     embedder either pinned a non-tombstone strategy or wired a
//     partial Store; either way the cascade is not enforced and the
//     refresh proceeds.
//   - The exchanged record carries no GrantID. A refresh chain
//     without an authorize-side grant has no tombstone to consult;
//     the rare case that surfaces here is a legacy chain issued
//     before the GrantID column landed.
//
// Returns true when the request may proceed; false when a response
// has already been written.
func enforceGrantTombstoneMintRefusal(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	exchanged *refresh.Exchanged,
) bool {
	if deps.RevocationStrategy != store.RevocationStrategyGrantTombstone {
		return true
	}
	if deps.GrantRevocations == nil || exchanged == nil || exchanged.GrantID == "" {
		return true
	}
	revoked, err := deps.GrantRevocations.IsRevoked(ctx, exchanged.GrantID, "", exchanged.IssuedAt)
	if err != nil {
		// Substore transport fault on the verify path: ADR 0025
		// §Error handling treats this as fatal because silently
		// allowing the request would re-introduce a cascade gap.
		// Surface as server_error rather than invalid_grant so the
		// embedder's monitoring distinguishes a substore outage from a
		// legitimate revocation.
		writeError(w, http.StatusInternalServerError, errServerError, "")
		return false
	}
	if revoked {
		writeError(w, http.StatusBadRequest, errInvalidGrant, "refresh token rejected")
		return false
	}
	return true
}

// revokePriorOpaqueAT revokes every opaque access token tied to
// grantID when the rotation issues an opaque-format token (ADR 0024
// §"Refresh-rotation revocation of prior AT"). The function is a
// no-op when:
//
//   - The deployment runs JWT-only (no OpaqueAccessTokens substore
//     wired). The JWT path leaves prior tokens alive on rotation by
//     design — see [issueRefreshResponse].
//   - The active per-audience policy returns
//     [store.AccessTokenFormatJWT] for this resource. A mixed-format
//     deployment may choose JWT for one audience and opaque for
//     another; only the opaque branch revokes.
//   - GrantID is empty. Refresh rotation always carries the parent
//     grant id; an empty value indicates a programmer error in the
//     exchanger. Treat the cascade as a silent no-op so a future
//     refactor that surfaces empty grants does not crash the path.
//
// Errors from RevokeByGrant are swallowed: the caller has not yet
// minted the new access token, so a partial revocation does not leave
// a credential in a contradictory state. The next token-endpoint
// request hits the same revocation path again because the substore
// keeps the row until GC; idempotency ensures a retry recovers.
func revokePriorOpaqueAT(ctx context.Context, deps Deps, resource, grantID string) {
	if deps.OpaqueAccessTokens == nil || grantID == "" {
		return
	}
	format := store.AccessTokenFormatJWT
	if deps.AccessTokenFormatFor != nil {
		format = deps.AccessTokenFormatFor(resource)
	}
	if format != store.AccessTokenFormatOpaque {
		return
	}
	_, _ = deps.OpaqueAccessTokens.RevokeByGrant(ctx, grantID)
}

// refreshChainRevocationStore returns the [store.GrantRevocationStore]
// the refresh exchanger uses to tombstone replayed chains. The hook
// fires only when the active strategy is
// [store.RevocationStrategyGrantTombstone] AND the embedder wired a
// non-nil substore. Other strategies leave the JWT-AT cascade to the
// per-token JTI denylist (legacy ADR 0013 path) or skip JWT
// revocation entirely; both keep the refresh-chain revoke alive but
// suppress the tombstone write so the wire shape matches the
// strategy's documented behaviour.
func refreshChainRevocationStore(deps Deps) store.GrantRevocationStore {
	if deps.RevocationStrategy != store.RevocationStrategyGrantTombstone {
		return nil
	}
	return deps.GrantRevocations
}

// refreshChainTombstoneTTL bounds the lifetime of a tombstone written
// by the refresh chain-revoke cascade. The value is computed as
// (access_token_TTL + 5 minute grace) so any access token issued
// before the cascade is guaranteed to have expired before its
// tombstone disappears. The grace covers clock skew between the OP
// and resource servers consulting [store.GrantRevocationStore.IsRevoked];
// 5 minutes is the same floor the access-token registry GC uses. A
// zero value flows through to [refresh.ExchangerConfig.GrantTombstoneTTL]
// and disables GC, which is safe but unbounded in storage.
func refreshChainTombstoneTTL(deps Deps) time.Duration {
	if deps.AccessTokenTTL <= 0 {
		return 0
	}
	return deps.AccessTokenTTL + 5*time.Minute
}
