package tokenendpoint

import (
	"context"
	"errors"
	"net/http"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/internal/grants/refresh"
	"github.com/libraz/go-oidc-provider/internal/oidcscope"
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
	dpopOut, client, ok := authenticateWithDPoP(ctx, w, r, deps, grantTypeRefreshToken)
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
	if !preflightRefreshBeforeConsume(ctx, w, r, deps, client, in, dpopOut) {
		return
	}
	// Resolve authorization_details before opening the transaction. A SQL
	// transaction begins a read snapshot on its first lookup; doing this
	// preflight through the transaction immediately before Consume can leave
	// SQLite's WAL writer with a stale snapshot and produce SQLITE_BUSY_SNAPSHOT.
	// The effective details are immutable request state by the time Consume
	// starts, so both paths can reuse the same result.
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
	if deps.Transactions != nil {
		handleRefreshTokenTransaction(
			ctx,
			w,
			r,
			deps,
			client,
			in,
			dpopOut,
			authorizationDetails,
			effectiveAuthorizationDetails,
		)
		return
	}
	// No transaction to settle behind, but the response is still staged so a
	// replayed chain is retired before the client is told its token was
	// refused — the same ordering the transactional path gives.
	var cascade replayCascade
	var rotation rotationOutcome
	staged := newStagedResponseWriter()
	completeRefreshToken(ctx, staged, r, deps, client, in, dpopOut, nil, effectiveAuthorizationDetails, false, false, &cascade, &rotation)
	// Each write above landed as it ran, so a recorded rotation is durable.
	rotation.emit(ctx, deps)
	cascade.run(ctx, deps)
	staged.copyTo(w)
}

// rotationOutcome carries the token.refreshed record of a rotation out of
// the exchange, so it is emitted only once the rotation is durable: after
// Commit on the transactional path, where an attempt that loses a commit
// race or rolls back rotated nothing.
type rotationOutcome struct {
	event *audit.Event
}

// record keeps ev for [rotationOutcome.emit].
func (o *rotationOutcome) record(ev audit.Event) {
	if o != nil {
		o.event = &ev
	}
}

// emit raises the recorded event, if a rotation recorded one.
func (o *rotationOutcome) emit(ctx context.Context, deps Deps) {
	if o != nil && o.event != nil {
		deps.audit().Emit(ctx, *o.event)
	}
}

func completeRefreshToken(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	deps Deps,
	client *store.Client,
	in refreshInputs,
	dpopOut *dpopOutcome,
	requestedAuthorizationDetails []map[string]any,
	authorizationDetails []map[string]any,
	revalidateAuthorizationDetails bool,
	transactional bool,
	cascade *replayCascade,
	rotation *rotationOutcome,
) (rollback bool) {
	exchanged, ok := exchangeRefresh(ctx, w, deps, client.ID, in, cascade)
	if !ok {
		return rollback
	}
	if revalidateAuthorizationDetails && !revalidateRefreshAuthorizationDetails(
		ctx,
		w,
		deps,
		exchanged,
		requestedAuthorizationDetails,
		authorizationDetails,
	) {
		// The response is a protocol rejection, but the Consume that
		// preceded this barrier must not become durable. The transaction
		// caller uses this result to roll back rather than committing the
		// stale authorization-details decision.
		return true
	}
	if !checkTokenScopeAllowlist(w, deps, client.ID, exchanged.Scope) {
		return rollback
	}
	if !requireRegisteredScopes(w, client, exchanged.Scope) {
		return rollback
	}
	if !enforceStrictOfflineAccess(w, deps, exchanged.BoundScope, exchanged.Origin) {
		return rollback
	}
	if !enforceDPoPRefreshBinding(w, deps, dpopOut, exchanged.DPoPJKT) {
		return rollback
	}
	if !requireMTLSMatch(w, r, deps, exchanged.MTLSCertThumbprint) {
		return rollback
	}
	binding := tokenBinding{
		DPoPJKT:        dpopOut.JKT,
		MTLSThumbprint: exchanged.MTLSCertThumbprint,
	}
	if !enforceSenderConstraint(w, deps, binding) {
		return rollback
	}
	user, ok := requireLiveRefreshSubject(ctx, w, deps, client.ID, exchanged, cascade)
	if !ok {
		return rollback
	}
	issueRefreshResponse(ctx, w, deps, client, exchanged, user, binding, authorizationDetails, transactional, rotation)
	return false
}

// requireLiveRefreshSubject resolves the chain's subject before anything
// is minted, grace retries included. A subject the user store no longer
// holds arms cascade to tear the grant down at the settle point and
// answers invalid_grant; a store fault answers server_error. A chain a
// custom grant rooted records a public subject, so its user-store
// subject comes from the grant it descends from (a token exchange's
// subject_token grant); with no such grant the handler, not the user
// store, vouched for the subject and it is not looked up. Returns false
// when a response has already been written.
func requireLiveRefreshSubject(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	clientID string,
	exchanged *refresh.Exchanged,
	cascade *replayCascade,
) (*store.User, bool) {
	subject := exchanged.Subject
	if !grantIsOwnConsent(exchanged.Origin) {
		lineage, err := findGrant(ctx, deps, exchanged.GrantID)
		if err != nil {
			endpointsupport.WriteOAuthError(w, http.StatusInternalServerError, errServerError, "")
			return nil, false
		}
		if lineage == nil {
			return nil, true
		}
		subject = lineage.Subject
	}
	user, err := lookupLiveSubject(ctx, deps, subject)
	if err != nil {
		if errors.Is(err, errSubjectDeprovisioned) {
			cascade.armDeprovisioned(deprovisionedRedemption{
				ClientID:  clientID,
				Subject:   subject,
				GrantType: grantTypeRefreshToken,
				GrantID:   exchanged.GrantID,
			})
		}
		writeSubjectLookupError(w, err)
		return nil, false
	}
	return user, true
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
	requestedAuthorizationDetails []map[string]any,
	authorizationDetails []map[string]any,
) {
	var cascade replayCascade
	run := func() (*stagedResponseWriter, error) {
		return runRefreshTokenTransaction(
			ctx,
			r,
			deps,
			client,
			in,
			dpopOut,
			requestedAuthorizationDetails,
			authorizationDetails,
			&cascade,
		)
	}
	staged, err := run()
	if errors.Is(err, store.ErrConflict) {
		// A backend that checks consumed_at only at Commit (an optimistic
		// conditional write) lets two concurrent presentations of one token
		// both pass Consume; the loser learns of the race here. Its writes
		// were discarded, so one re-run sees the winner's committed
		// consumed_at and ends exactly as a serialising backend would:
		// invalid_grant with the RFC 9700 §2.2.2 cascade armed, or the grace
		// response.
		staged, err = run()
	}
	// The transaction has settled by the time the helper returns, so the direct
	// substore handles are free and a replayed chain is retired here — before
	// the client is told anything, and in both settle directions.
	cascade.run(ctx, deps)
	if err != nil {
		endpointsupport.WriteOAuthError(w, http.StatusInternalServerError, errServerError, "")
		return
	}
	staged.copyTo(w)
}

// runRefreshTokenTransaction stages the refresh exchange behind a transaction
// and settles it, handing the staged response back for the caller to forward.
// A non-nil error means the transaction could not be opened or could not be
// settled, and the caller owes the client a server_error.
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
	requestedAuthorizationDetails []map[string]any,
	authorizationDetails []map[string]any,
	cascade *replayCascade,
) (*stagedResponseWriter, error) {
	tx, err := deps.Transactions.BeginTx(ctx)
	if err != nil {
		return nil, err
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
	var rotation rotationOutcome
	rollback := completeRefreshToken(
		ctx,
		staged,
		r,
		txDeps,
		client,
		in,
		dpopOut,
		requestedAuthorizationDetails,
		authorizationDetails,
		true,
		true,
		cascade,
		&rotation,
	)
	// Preserve OAuth rejection semantics that intentionally finalize token
	// state (notably tombstoned-grant mint refusal, which rejects only after
	// Consume has spent the presented token) while rolling back server-side
	// failures in token assembly/persistence. Request-shape and narrowing
	// rejections are handled before Exchange.
	if rollback || staged.status >= http.StatusInternalServerError || staged.status == 0 {
		return staged, nil
	}
	if err := tx.Commit(); err != nil {
		if cascade.armed() {
			// A replay stages nothing: Consume refused the presented token, so
			// the transaction carries no write whose loss the client needs to
			// hear about. Reporting the settle fault as server_error would
			// replace a correct RFC 6749 §5.2 invalid_grant with a 5xx and bury
			// the finding; the cascade retires the chain either way.
			return staged, nil
		}
		return nil, err
	}
	rotation.emit(ctx, deps)
	return staged, nil
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
		endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errInvalidRequest, "refresh_token is required")
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
		Clock:              deps.Clock,
		GraceTTL:           deps.RefreshTokenGraceTTL,
		Audit:              deps.audit(),
		DeferReplayCascade: true,
	})
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
		endpointsupport.WriteOAuthError(w, http.StatusInternalServerError, errServerError, "")
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
		endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errInvalidGrant, "refresh token rejected")
	case errors.Is(err, refresh.ErrScopeWidening):
		endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errInvalidScope,
			"requested scope exceeds the original grant")
	default:
		endpointsupport.WriteOAuthError(w, http.StatusInternalServerError, errServerError, "")
	}
}
