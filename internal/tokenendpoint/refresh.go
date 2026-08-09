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
	// Proof verification, client authentication, and the proof's replay
	// marking run in the order [authenticateWithDPoP] documents. The
	// bound-chain invariants (proof required when the presented refresh
	// token was DPoP-bound, jkt match) depend on the exchange outcome
	// and are enforced post-exchange via [enforceDPoPRefreshBinding].
	ctx := r.Context()
	dpopOut, client, ok := authenticateWithDPoP(ctx, w, r, deps)
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
	effectiveAuthorizationDetails, ok := preflightRefreshAuthorizationDetails(
		ctx,
		w,
		deps,
		in.Token,
		authorizationDetails,
	)
	if !ok {
		return
	}
	// No transaction to settle behind, but the response is still staged so a
	// replayed chain is retired before the client is told its token was
	// refused — the same ordering the transactional path gives.
	var cascade replayCascade
	staged := newStagedResponseWriter()
	completeRefreshToken(ctx, staged, r, deps, client, in, dpopOut, effectiveAuthorizationDetails, &cascade)
	cascade.run(ctx, deps)
	staged.copyTo(w)
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
	cascade *replayCascade,
) {
	exchanged, ok := exchangeRefresh(ctx, w, deps, client.ID, in, cascade)
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
//
// The RFC 9700 §2.2.2 replay cascade is the one mutation that is NOT staged:
// it runs against the non-transactional substore handles once the transaction
// has settled, in the commit and the rollback direction alike, and before the
// response reaches the client. See [replayCascade] for why it cannot live
// inside the transaction.
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
	var cascade replayCascade
	staged, ok := runRefreshTokenTransaction(ctx, r, deps, client, in, dpopOut, authorizationDetails, &cascade)
	// The transaction has settled by the time the helper returns, so the direct
	// substore handles are free and a replayed chain is retired here — before
	// the client is told anything, and in both settle directions.
	cascade.run(ctx, deps)
	if !ok {
		writeError(w, http.StatusInternalServerError, errServerError, "")
		return
	}
	staged.copyTo(w)
}

// runRefreshTokenTransaction stages the refresh exchange behind a transaction
// and settles it, handing the staged response back for the caller to forward.
// ok=false means the transaction could not be opened or could not be settled,
// and the caller owes the client a server_error.
//
// The staged response is deliberately NOT written here: the caller runs the
// replay cascade between the settle and the write, so nothing observable
// depends on how the HTTP layer happens to buffer the response.
func runRefreshTokenTransaction(
	ctx context.Context,
	r *http.Request,
	deps Deps,
	client *store.Client,
	in refreshInputs,
	dpopOut *dpopOutcome,
	authorizationDetails []map[string]any,
	cascade *replayCascade,
) (*stagedResponseWriter, bool) {
	tx, err := deps.Transactions.BeginTx(ctx)
	if err != nil {
		return nil, false
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
	effectiveAuthorizationDetails, ok := preflightRefreshAuthorizationDetails(
		ctx,
		staged,
		txDeps,
		in.Token,
		authorizationDetails,
	)
	if !ok {
		return staged, true
	}
	completeRefreshToken(ctx, staged, r, txDeps, client, in, dpopOut, effectiveAuthorizationDetails, cascade)
	// Preserve OAuth rejection semantics that intentionally finalize token
	// state (notably tombstoned-grant mint refusal, which rejects only after
	// Consume has spent the presented token) while rolling back server-side
	// failures in token assembly/persistence. Request-shape and narrowing
	// rejections are handled before Exchange.
	if staged.status >= http.StatusInternalServerError || staged.status == 0 {
		return staged, true
	}
	if err := tx.Commit(); err != nil {
		if cascade.armed() {
			// A replay stages nothing: Consume refused the presented token, so
			// the transaction carries no write whose loss the client needs to
			// hear about. Reporting the settle fault as server_error would
			// replace a correct RFC 6749 §5.2 invalid_grant with a 5xx and bury
			// the finding; the cascade retires the chain either way.
			return staged, true
		}
		return nil, false
	}
	return staged, true
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
	if err == nil && rec == nil {
		// A nil record alongside a nil error violates the store contract.
		// Treat it as a miss: the preflight has nothing to check against and
		// the exchanger below still refuses the token.
		err = store.ErrNotFound
	}
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

// preflightRefreshAuthorizationDetails resolves and narrows the RFC 9396
// authorization_details before Exchange consumes the predecessor refresh
// token. The live Grant is authoritative while it carries details; the
// refresh-token snapshot remains the fallback for missing or deliberately
// sparse grants. When called with transaction-bound deps, this selection and
// the later Consume share the same transactional view.
//
// The returned effective details are passed unchanged into issuance. Repeating
// the subset check after Consume would let a concurrent Grant Management update
// turn a valid preflight into a protocol rejection that strands the predecessor.
func preflightRefreshAuthorizationDetails(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	token string,
	requested []map[string]any,
) ([]map[string]any, bool) {
	rec, err := deps.RefreshTokens.Find(ctx, token)
	if err == nil && rec == nil {
		// A nil record alongside a nil error violates the store contract.
		// Treat it as a miss so the presented token earns the same
		// invalid_grant an unknown handle earns rather than a distinguishable
		// 5xx; the exchanger below still refuses to issue against it.
		err = store.ErrNotFound
	}
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// Preserve the exchanger's invalid_grant mapping for unknown or
			// expired handles.
			return nil, true
		}
		writeError(w, http.StatusInternalServerError, errServerError, "")
		return nil, false
	}
	if rec.ConsumedAt != nil {
		// Replay detection and grace-window response recovery remain owned by
		// the exchanger. Neither path issues a new response from these details.
		return nil, true
	}

	granted := cloneAuthorizationDetails(rec.AuthorizationDetails)
	if rec.GrantID != "" && deps.Grants != nil {
		grant, findErr := deps.Grants.Find(ctx, rec.GrantID)
		switch {
		case findErr == nil && grant == nil:
			writeError(w, http.StatusInternalServerError, errServerError, "")
			return nil, false
		case findErr == nil && len(grant.AuthorizationDetails) > 0:
			granted = cloneAuthorizationDetails(grant.AuthorizationDetails)
		case findErr == nil, errors.Is(findErr, store.ErrNotFound):
			// A sparse or missing grant uses the refresh-token snapshot.
		default:
			writeError(w, http.StatusInternalServerError, errServerError, "")
			return nil, false
		}
	}

	return reduceAuthorizationDetails(w, requested, granted)
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

// newRefreshExchanger builds the [refresh.Exchanger] the refresh path
// drives. The exchanger always defers the RFC 9700 §2.2.2 chain cascade:
// the token endpoint owns when it runs (see [replayCascade]) so the same
// ordering holds whether or not the request took the transactional path.
func newRefreshExchanger(deps Deps) (*refresh.Exchanger, error) {
	return refresh.NewExchanger(refresh.ExchangerConfig{
		Store:              deps.RefreshTokens,
		Clock:              deps.clockFunc(),
		GraceTTL:           deps.RefreshTokenGraceTTL,
		Audit:              deps.audit(),
		GrantRevocations:   refreshChainRevocationStore(deps),
		GrantTombstoneTTL:  refreshChainTombstoneTTL(deps),
		DeferReplayCascade: true,
	})
}

// replayCascade carries a detected refresh-token replay out of the
// exchange so the RFC 9700 §2.2.2 chain cascade runs once the surrounding
// transaction has settled, against non-transactional substore handles.
//
// Running the cascade on transaction-bound handles bounds it by whatever
// action limit the backend's transaction imposes, and a chain long enough
// to exceed it would be retired only in part — breadth-first from the
// root, so the newest node, the one an attacker presenting a stolen token
// holds, would survive. A rollback would discard the cascade entirely.
// Deferring past the settle point removes both failure modes, and the
// replay is the finding whichever way the transaction went.
type replayCascade struct {
	// token is the refresh_token the client presented, empty until a
	// replay is detected. Nothing else has to travel: the chain root and
	// the grant it belongs to are derived by walking parent pointers from
	// this value.
	token string
}

// arm records that presented was replayed, so the cascade runs at the
// next settle point.
func (c *replayCascade) arm(presented string) {
	if c == nil {
		return
	}
	c.token = presented
}

// armed reports whether a replay was detected during the exchange.
func (c *replayCascade) armed() bool { return c != nil && c.token != "" }

// run retires the replayed chain through non-transactional substores. It
// is a no-op unless a replay was detected and it never reports failure:
// the exchanger raises a warn-level audit event on a transport fault and
// the client keeps the invalid_grant answer it has already been given.
func (c *replayCascade) run(ctx context.Context, deps Deps) {
	if !c.armed() {
		return
	}
	exchanger, err := newRefreshExchanger(deps)
	if err != nil {
		// Unreachable in practice: the same construction already succeeded
		// during the exchange that detected the replay. Dropping the
		// cascade is the best-effort contract's answer, and the replay
		// audit event has already been emitted.
		return
	}
	exchanger.RevokeReplayedChain(ctx, c.token)
}

// exchangeRefresh runs the [refresh.Exchanger] and translates sentinel
// errors into the wire form. A detected replay arms cascade so the caller
// retires the chain after the surrounding transaction settles. Returns
// ok=false when a response has already been written.
func exchangeRefresh(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	clientID string,
	in refreshInputs,
	cascade *replayCascade,
) (*refresh.Exchanged, bool) {
	exchanger, err := newRefreshExchanger(deps)
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
		if errors.Is(err, refresh.ErrTokenReplayed) {
			cascade.arm(in.Token)
		}
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
// codes. Replay *detection* lives inside [refresh.Exchanger]; the chain
// cascade it implies is armed by [exchangeRefresh] and run at the request's
// settle point, so this function only has to surface the right wire code.
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
// id). Failure on any step writes a 500. The provider's transactional path
// rolls the staged Consume back; non-transactional embeddings cannot
// coordinate that rollback and rely on their substore atomicity contract.
//
// binding is the sender-constraint summary the rotated tokens inherit.
// For DPoP it is either the verified proof's thumbprint (request
// presented a proof) or the consumed record's bound thumbprint
// (chain was already bound and the proof simply matched); for mTLS
// it is always the consumed record's thumbprint (mTLS does not
// admit mid-chain upgrades). Both cases collapse to a single source
// of truth on the wire and on the persisted rotated record.
//
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
) {
	response, found, err := loadRefreshRetryResponse(ctx, deps, exchanged.ConsumedID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, errServerError, "")
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
		writeError(w, http.StatusBadRequest, errInvalidGrant, "refresh token rejected")
		return
	}
	// A grace retry may not widen or otherwise change the effective scope
	// of the response originally cached for this predecessor.
	if response.Scope != joinScope(exchanged.Scope) {
		writeError(w, http.StatusBadRequest, errInvalidGrant, "refresh token retry does not match original exchange")
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
	if binding.constrained() {
		reissueGraceAccessToken(ctx, w, deps, client, exchanged, binding, &response)
		return
	}
	writeSuccess(w, response)
}

func issueRefreshResponse(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	client *store.Client,
	exchanged *refresh.Exchanged,
	binding tokenBinding,
	authorizationDetails []map[string]any,
) {
	if exchanged.InGrace {
		serveGraceRetry(ctx, w, deps, client, exchanged, binding)
		return
	}
	now := deps.now().UTC()
	authCtx := refreshAuthContext(ctx, deps, exchanged)
	if err := requireAuthTimeForIDToken(client, exchanged.Scope, authCtx.AuthTime); err != nil {
		writeError(w, http.StatusInternalServerError, errServerError, "required auth_time is unavailable")
		return
	}
	// Opaque-format chains revoke the prior access token atomically with
	// the new mint. Resource servers calling /oidc/introspect on every
	// request observe the revocation immediately, so the
	// stolen-but-still-valid window collapses to clock-skew. The JWT
	// path deliberately leaves prior tokens alive: doing otherwise would
	// force every JWT verification through introspection, defeating the
	// JWT optimisation that motivated the registry design. Revocation
	// runs BEFORE the new mint so a colliding hash on Save
	// (impossible-by-construction with 256-bit entropy) cannot leave the
	// chain in a half-revoked state.
	if err := revokePriorOpaqueAT(ctx, deps, exchanged.Resource, exchanged.GrantID); err != nil {
		writeError(w, http.StatusInternalServerError, errServerError, "")
		return
	}
	// Mint refusal under a tombstoned grant: under the
	// grant-tombstone strategy, refuse to mint a fresh access token when
	// the underlying grant has already been tombstoned. Without this
	// check a refresh racing a /end_session or code-replay cascade could
	// slip a fresh AT through ahead of the tombstone's observable effect
	// on resource-server lookups. The check surfaces as invalid_grant
	// per RFC 6749 §5.2 because the grant was legitimately revoked, the
	// refresh token is no longer usable, and the failure is a property
	// of the grant rather than of the request shape.
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
// current binding, and the grant-tombstone mint-refusal guard runs
// exactly as it does on a first-issue refresh so a replay cannot slip a
// fresh access token past a grant that has since been revoked.
func reissueGraceAccessToken(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	client *store.Client,
	exchanged *refresh.Exchanged,
	binding tokenBinding,
	response *successResponse,
) {
	if !enforceGrantTombstoneMintRefusal(ctx, w, deps, exchanged) {
		return
	}
	now := deps.now().UTC()
	authCtx := refreshAuthContext(ctx, deps, exchanged)
	publicSubject := exchanged.Subject
	if !exchanged.SubjectPublic {
		projected, err := projectPublicSubject(ctx, deps, exchanged.Subject, client)
		if err != nil {
			writeError(w, http.StatusInternalServerError, errServerError, "")
			return
		}
		publicSubject = projected
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
		response.AuthorizationDetails,
		exchanged.AccessTokenExtra,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, errServerError, "")
		return
	}
	response.AccessToken = accessToken
	response.TokenType = binding.tokenTypeFor()
	response.ExpiresIn = int64(deps.AccessTokenTTL.Seconds())
	writeSuccess(w, *response)
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

// enforceGrantTombstoneMintRefusal implements the mint- refusal check
// on the refresh path: under [store.RevocationStrategyGrantTombstone]
// the OP refuses to sign a fresh access token when the underlying
// grant has already been tombstoned. The lookup uses the consumed
// refresh token's IssuedAt (its [store.RefreshToken.CreatedAt]) so
// the verifier's "iat <= RevokedAt" rule is honoured: a chain that
// was minted strictly before the tombstone is rejected even if the
// wall-clock race produced an iat of "RevokedAt".
//
// The function is a no-op when:
//
//   - The strategy is not [store.RevocationStrategyGrantTombstone].
//     [store.RevocationStrategyJTIRegistry] preserves the per-JTI
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
		// Substore transport fault on the verify path: handling treats this
		// as fatal because silently allowing the request would re-introduce
		// a cascade gap. Surface as server_error rather than invalid_grant
		// so the embedder's monitoring distinguishes a substore outage from
		// a legitimate revocation.
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
// grantID when the rotation issues an opaque-format token. The
// function is a no-op when:
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

// refreshChainRevocationStore returns the
// [store.GrantRevocationStore] the refresh exchanger uses to
// tombstone replayed chains. The hook fires only when the active
// strategy is [store.RevocationStrategyGrantTombstone] AND the
// embedder wired a non-nil substore. Other strategies leave the
// JWT-AT cascade to the per-token JTI denylist (legacy path) or skip
// JWT revocation entirely; both keep the refresh-chain revoke alive
// but suppress the tombstone write so the wire shape matches the
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
