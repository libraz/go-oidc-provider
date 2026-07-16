package tokenendpoint

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/authorize"
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
	authorizationDetails, ok := parseTokenAuthorizationDetails(w, r, deps, client)
	if !ok {
		return
	}
	if !preflightRefreshBeforeConsume(ctx, w, r, deps, client.ID, in, dpopOut) {
		return
	}
	if deps.Transactions != nil {
		handleRefreshTokenTransaction(ctx, w, r, deps, client, in, dpopOut, authorizationDetails)
		return
	}
	completeRefreshToken(ctx, w, r, deps, client, in, dpopOut, authorizationDetails)
}

func completeRefreshToken(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	deps Deps,
	client *store.Client,
	in refreshInputs,
	dpopOut *dpopOutcome,
	authorizationDetails []map[string]any,
) {
	exchanged, ok := exchangeRefresh(ctx, w, deps, client.ID, in)
	if !ok {
		return
	}
	if !checkTokenScopeAllowlist(w, deps, client.ID, exchanged.Scope) {
		return
	}
	if !enforceStrictOfflineAccess(w, deps, exchanged.Scope, exchanged.Origin) {
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
	issueRefreshResponse(ctx, w, deps, client, exchanged, binding, authorizationDetails)
}

// handleRefreshTokenTransaction stages every post-preflight refresh mutation
// behind a transaction and only forwards the buffered response after Commit.
// A signing/JWE/cache/write failure consequently rolls Consume back instead of
// stranding the predecessor refresh token.
func handleRefreshTokenTransaction(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	deps Deps,
	client *store.Client,
	in refreshInputs,
	dpopOut *dpopOutcome,
	authorizationDetails []map[string]any,
) {
	tx, err := deps.Transactions.BeginTx(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, errServerError, "")
		return
	}
	defer func() { _ = tx.Rollback() }()
	txDeps := deps
	txDeps.Transactions = nil
	txDeps.RefreshTokens = tx.RefreshTokens()
	txDeps.Grants = tx.Grants()
	txDeps.AccessTokens = tx.AccessTokens()
	txDeps.OpaqueAccessTokens = tx.OpaqueAccessTokens()
	txDeps.GrantRevocations = tx.GrantRevocations()
	staged := newStagedResponseWriter()
	completeRefreshToken(ctx, staged, r, txDeps, client, in, dpopOut, authorizationDetails)
	// Preserve OAuth rejection semantics that intentionally consume a token
	// (notably replay detection and scope-widening) while rolling back only
	// server-side failures in token assembly/persistence. Preflight covers the
	// sender-constraint rejection cases before a transaction is opened.
	if staged.status >= http.StatusInternalServerError || staged.status == 0 {
		staged.copyTo(w)
		return
	}
	if err := tx.Commit(); err != nil {
		writeError(w, http.StatusInternalServerError, errServerError, "")
		return
	}
	staged.copyTo(w)
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

func preflightRefreshBeforeConsume(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	deps Deps,
	clientID string,
	in refreshInputs,
	dpopOut *dpopOutcome,
) bool {
	rec, err := deps.RefreshTokens.Find(ctx, in.Token)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return true
		}
		writeError(w, http.StatusInternalServerError, errServerError, "")
		return false
	}
	if rec.ConsumedAt != nil {
		return true
	}
	if rec.ClientID != clientID {
		writeError(w, http.StatusBadRequest, errInvalidGrant, "refresh token rejected")
		return false
	}
	if !rec.ExpiresAt.IsZero() && deps.now().UTC().After(rec.ExpiresAt) {
		writeError(w, http.StatusBadRequest, errInvalidGrant, "refresh token rejected")
		return false
	}
	scope, ok := preflightRefreshScope(w, rec.Scope, in.RequestedScope)
	if !ok {
		return false
	}
	if deps.Scopes != nil && !checkTokenScopeAllowlist(w, deps, clientID, scope) {
		return false
	}
	if !enforceStrictOfflineAccess(w, deps, scope, rec.Origin) {
		return false
	}
	// Sender-constrained refresh tokens must reject a missing or mismatched
	// proof before Exchange consumes their single-use record. The post-exchange
	// checks remain below as defence in depth and cover the grace path, whose
	// consumed record intentionally bypasses this preflight.
	if !enforceDPoPRefreshBinding(w, deps, dpopOut, rec.DPoPJKT) {
		return false
	}
	return requireMTLSMatch(w, r, deps, rec.MTLSCertThumbprint)
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
			writeError(w, http.StatusBadRequest, errInvalidScope,
				"requested scope exceeds the original grant")
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
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
//
//nolint:gocognit // Protocol-mandated issuance order keeps each failure boundary explicit.
func issueRefreshResponse(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	client *store.Client,
	exchanged *refresh.Exchanged,
	binding tokenBinding,
	requestedAuthorizationDetails []map[string]any,
) {
	if exchanged.InGrace {
		response, err := loadRefreshRetryResponse(ctx, deps, exchanged.ConsumedID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, errServerError, "")
			return
		}
		// A grace retry may not widen or otherwise change the effective scope
		// of the response originally cached for this predecessor.
		if response.Scope != joinScope(exchanged.Scope) {
			writeError(w, http.StatusBadRequest, errInvalidGrant, "refresh token retry does not match original exchange")
			return
		}
		writeSuccess(w, response)
		return
	}
	now := deps.now().UTC()
	authCtx := refreshAuthContext(ctx, deps, exchanged)
	if err := requireAuthTimeForIDToken(client, exchanged.Scope, authCtx.AuthTime); err != nil {
		writeError(w, http.StatusInternalServerError, errServerError, "required auth_time is unavailable")
		return
	}
	authorizationDetails, ok := reduceAuthorizationDetails(w, requestedAuthorizationDetails, authCtx.AuthorizationDetails)
	if !ok {
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
	if err := revokePriorOpaqueAT(ctx, deps, exchanged.Resource, exchanged.GrantID); err != nil {
		writeError(w, http.StatusInternalServerError, errServerError, "")
		return
	}
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
	publicSubject := exchanged.Subject
	if !exchanged.SubjectPublic {
		var err error
		publicSubject, err = projectPublicSubject(ctx, deps, exchanged.Subject, client)
		if err != nil {
			writeError(w, http.StatusInternalServerError, errServerError, "")
			return
		}
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
		authorizationDetails,
		exchanged.AccessTokenExtra,
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
		Claims:   authCtx.Claims,
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
	response := successResponse{
		AccessToken:          accessToken,
		TokenType:            binding.tokenTypeFor(),
		ExpiresIn:            int64(deps.AccessTokenTTL.Seconds()),
		IDToken:              idToken,
		Scope:                joinScope(exchanged.Scope),
		AuthorizationDetails: cloneAuthorizationDetails(authorizationDetails),
		GrantID:              grantIDForResponse(deps, exchanged.GrantID),
	}
	if err := rotateRefreshToken(ctx, deps, client, refreshExchangedWithAuthorizationDetails(exchanged, authorizationDetails), binding, &response); err != nil {
		writeError(w, http.StatusInternalServerError, errServerError, "")
		return
	}
	writeSuccess(w, response)
}

func refreshExchangedWithAuthorizationDetails(exchanged *refresh.Exchanged, details []map[string]any) *refresh.Exchanged {
	if exchanged == nil {
		return nil
	}
	out := *exchanged
	out.AuthorizationDetails = cloneAuthorizationDetails(details)
	return &out
}

func refreshAuthContext(ctx context.Context, deps Deps, exchanged *refresh.Exchanged) authContext {
	fallback := lookupAuthContext(ctx, deps, exchanged.GrantID)
	out := fallback
	if !exchanged.AuthTime.IsZero() {
		out.AuthTime = exchanged.AuthTime.Unix()
	}
	if exchanged.ACR != "" {
		out.ACR = exchanged.ACR
	}
	if len(exchanged.AMR) > 0 {
		out.AMR = append([]string(nil), exchanged.AMR...)
	}
	// Grant Management replace/merge mutates the grant, not historical
	// refresh-token records. While the grant exists it is the source of
	// truth for RFC 9396 authorization_details; the record snapshot is
	// only a fallback for custom grants or legacy/missing-grant chains.
	if len(out.AuthorizationDetails) == 0 && len(exchanged.AuthorizationDetails) > 0 {
		out.AuthorizationDetails = cloneAuthorizationDetails(exchanged.AuthorizationDetails)
	}
	return out
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
	Claims   *authorize.ClaimsRequest

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
		ACR:       idTokenACRForClaims(in.ACR, in.Claims),
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
	response *successResponse,
) error {
	issuer, err := refresh.NewIssuer(refresh.IssuerConfig{
		Store: deps.RefreshTokens,
		Clock: deps.clockFunc(),
		TTL:   pickRefreshTokenTTL(deps, exchanged.Scope),
	})
	if err != nil {
		return err
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
	issue := refresh.IssueInput{
		ClientID:             client.ID,
		Subject:              exchanged.Subject,
		GrantID:              exchanged.GrantID,
		Scope:                append([]string(nil), exchanged.Scope...),
		Resource:             exchanged.Resource,
		ParentID:             &parent,
		DPoPJKT:              rotatedJKT,
		MTLSCertThumbprint:   binding.MTLSThumbprint,
		Nonce:                exchanged.Nonce,
		Origin:               exchanged.Origin,
		SubjectPublic:        exchanged.SubjectPublic,
		AuthTime:             exchanged.AuthTime,
		ACR:                  exchanged.ACR,
		AMR:                  append([]string(nil), exchanged.AMR...),
		AuthorizationDetails: cloneAuthorizationDetails(exchanged.AuthorizationDetails),
		AccessTokenExtra:     cloneClaimsMap(exchanged.AccessTokenExtra),
	}
	if len(deps.RefreshRetryEncryptionKeys) == 0 {
		token, err := issuer.Issue(ctx, issue)
		if err != nil {
			return err
		}
		response.RefreshToken = token
	} else {
		retries, ok := deps.RefreshTokens.(store.RefreshRetryResponseStore)
		if !ok {
			return errors.New("tokenendpoint: refresh store does not support durable retry responses")
		}
		token, successor, err := issuer.Prepare(issue)
		if err != nil {
			return err
		}
		response.RefreshToken = token
		sealed, err := sealRefreshRetryResponse(deps.RefreshRetryEncryptionKeys, parent, *response)
		if err != nil {
			return err
		}
		if err := retries.SaveRotationWithRetry(ctx, successor, sealed); err != nil {
			return err
		}
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
	return nil
}

func loadRefreshRetryResponse(ctx context.Context, deps Deps, predecessor string) (successResponse, error) {
	retries, ok := deps.RefreshTokens.(store.RefreshRetryResponseStore)
	if !ok {
		return successResponse{}, errors.New("tokenendpoint: refresh store does not support durable retry responses")
	}
	sealed, err := retries.LoadRetryResponse(ctx, predecessor)
	if err != nil {
		return successResponse{}, err
	}
	return openRefreshRetryResponse(deps.RefreshRetryEncryptionKeys, predecessor, sealed)
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
// RevokeByGrant errors are returned before a new access token is minted.
// This fail-closed ordering prevents a backend fault from creating a fresh
// bearer credential while a prior opaque credential remains active. The
// refresh-token grace path can safely retry the same idempotent cascade.
func revokePriorOpaqueAT(ctx context.Context, deps Deps, resource, grantID string) error {
	if deps.OpaqueAccessTokens == nil || grantID == "" {
		return nil
	}
	format := store.AccessTokenFormatJWT
	if deps.AccessTokenFormatFor != nil {
		format = deps.AccessTokenFormatFor(resource)
	}
	if format != store.AccessTokenFormatOpaque {
		return nil
	}
	_, err := deps.OpaqueAccessTokens.RevokeByGrant(ctx, grantID)
	return err
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
// zero/negative [Deps.AccessTokenTTL] is normalised to the token endpoint
// default here as a defensive backstop so a partially constructed Deps value
// cannot accidentally disable tombstone GC.
func refreshChainTombstoneTTL(deps Deps) time.Duration {
	ttl := deps.AccessTokenTTL
	if ttl <= 0 {
		ttl = defaultAccessTokenTTL
	}
	return ttl + 5*time.Minute
}
