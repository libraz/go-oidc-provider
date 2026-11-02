package tokenendpoint

import (
	"context"
	"net/http"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/internal/grants/refresh"
	"github.com/libraz/go-oidc-provider/internal/oidcscope"
	"github.com/libraz/go-oidc-provider/internal/pollinterval"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
)

// The polling grants (device_code and CIBA) share one poll discipline and
// one credential-assembly path; the types and helpers below carry what is
// common and take the differences as parameters.

// pollSpec parameterises [applyPollOutcome] for one polling grant.
type pollSpec struct {
	// observationFailedEvent and observationFailedMessage describe the
	// warn-level audit event emitted when persisting the poll observation fails.
	observationFailedEvent   string
	observationFailedMessage string
	// recordPoll persists the poll instant and the (possibly raised) interval.
	recordPoll func(ctx context.Context, now time.Time, interval time.Duration) error
	// reject emits the grant's rejected-poll audit event for a wire code.
	reject func(ctx context.Context, code string)
	// slowDown emits the slow_down audit event and applies the grant's
	// poll-abuse policy.
	slowDown func(ctx context.Context, decision pollinterval.Output)
	// expiredDescription and redeemedDescription are the error descriptions
	// for the expired and already-redeemed outcomes.
	expiredDescription  string
	redeemedDescription string
}

// applyPollOutcome persists the poll observation and writes the wire
// response for every outcome except emit. It returns true only for emit, the
// one outcome that lets the caller proceed to the authorization gates.
func applyPollOutcome(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	spec pollSpec,
	decision pollinterval.Output,
	now time.Time,
	currentInterval time.Duration,
	clientID string,
) bool {
	// A store fault while stamping the observation is non-fatal: the next poll
	// merely reads stale state, which fails open for a transient outage. The
	// warn event lets operators see an outage that quietly defeats slow_down.
	nextInterval := currentInterval
	if decision.Decision == pollinterval.OutcomeSlowDown {
		nextInterval = decision.NextInterval
	}
	if err := spec.recordPoll(ctx, now, nextInterval); err != nil {
		deps.audit().Emit(ctx, audit.Event{
			Name:     spec.observationFailedEvent,
			Level:    audit.LevelWarn,
			Message:  spec.observationFailedMessage,
			ClientID: clientID,
			Extras: map[string]any{
				"error": err.Error(),
			},
		})
	}
	reject := func(code, description string) bool {
		spec.reject(ctx, code)
		endpointsupport.WriteOAuthError(w, http.StatusBadRequest, code, description)
		return false
	}
	switch decision.Decision {
	case pollinterval.OutcomePending:
		return reject(errAuthorizationPending, "authorization request is still pending")
	case pollinterval.OutcomeSlowDown:
		spec.slowDown(ctx, decision)
		endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errSlowDown,
			"polling interval has been increased; back off and retry")
		return false
	case pollinterval.OutcomeDenied:
		return reject(errAccessDenied, "authorization request was denied")
	case pollinterval.OutcomeExpired:
		return reject(errExpiredToken, spec.expiredDescription)
	case pollinterval.OutcomeConsumed:
		// Only CIBA surfaces this outcome; its replay wire code is invalid_grant.
		return reject(errInvalidGrant, spec.redeemedDescription)
	case pollinterval.OutcomeEmit:
		return true
	case pollinterval.OutcomeInvalid:
		fallthrough
	default:
		endpointsupport.WriteOAuthError(w, http.StatusInternalServerError, errServerError, "")
		return false
	}
}

// polledRedemption is the approved authorization a polling grant redeems.
type polledRedemption struct {
	Subject  string
	Scope    []string
	Audience []string
	AuthTime time.Time
	ACR      string
}

// polledIssuance carries the per-grant differences of credential assembly.
type polledIssuance struct {
	// GrantID names the consent grant to record; empty allocates a fresh one.
	GrantID string
	// Origin labels the refresh chain.
	Origin store.RefreshTokenOrigin
	// DiscardGrantOnFailure deletes the grant when assembly fails or the
	// prepared credentials are cleaned up. The device grant keeps it: a
	// concurrent poll of the same authorization shares the record.
	DiscardGrantOnFailure bool
}

// preparedPolledResponse is a fully assembled token response awaiting the
// irreversible record consume.
type preparedPolledResponse struct {
	response       successResponse
	opaque         bool
	grantID        string
	discardOnClean bool
}

// issuedUnder names the prepared credentials for the grant-closure check.
// issuedAt is the redeemed record's IssuedAt: a revocation that completed
// after the authorization started closes the grant to this redemption.
func (p preparedPolledResponse) issuedUnder(issuedAt time.Time) issuedUnderGrant {
	return issuedUnderGrant{
		GrantID:      p.grantID,
		IssuedAt:     issuedAt,
		AccessToken:  p.response.AccessToken,
		RefreshToken: p.response.RefreshToken,
	}
}

func (p preparedPolledResponse) cleanup(ctx context.Context, deps Deps) {
	cleanupPreparedCredentials(ctx, deps, p.response.AccessToken, p.response.RefreshToken, p.opaque)
	if p.discardOnClean {
		discardGrant(ctx, deps, p.grantID)
	}
}

// preparePolledResponse completes every fallible token-assembly step before
// the record's irreversible Consume, so a signing, JWE or persistence fault
// leaves the approved ceremony retryable. The access token is minted
// first, then the id_token (only when scope contains openid), then the
// refresh token.
func preparePolledResponse(
	ctx context.Context,
	deps Deps,
	client *store.Client,
	red polledRedemption,
	user *store.User,
	binding tokenBinding,
	opt polledIssuance,
) (out preparedPolledResponse, err error) {
	now := deps.now().UTC()
	grantID, err := newGrantID(ctx, deps, grantIssuance{Lineage: grantLineageConsent, Grant: store.Grant{
		ID:       opt.GrantID,
		Subject:  red.Subject,
		ClientID: client.ID,
		Scope:    append([]string(nil), red.Scope...),
		AuthTime: red.AuthTime,
		ACR:      red.ACR,
	}})
	if err != nil {
		return preparedPolledResponse{}, err
	}
	resource := resourceOf(red.Audience)
	format := accessTokenFormat(deps, resource)
	var accessToken, idToken, refreshToken string
	defer func() {
		if err != nil {
			rollbackPolledResponse(ctx, deps, opt, grantID, accessToken, refreshToken, format)
		}
	}()
	// A zero auth_time means the substore kept none; the id_token then omits
	// the claim unless the client requires it, which blocks issuance here.
	authTime := tokens.UnixOrZero(red.AuthTime)
	if err = requireAuthTimeForIDToken(client, red.Scope, authTime); err != nil {
		return preparedPolledResponse{}, err
	}
	publicSubject, err := projectPublicSubject(ctx, deps, red.Subject, client)
	if err != nil {
		return preparedPolledResponse{}, err
	}
	chainID, err := refresh.NewChainID()
	if err != nil {
		return preparedPolledResponse{}, err
	}
	accessToken, err = mintAccessToken(
		ctx,
		deps,
		red.Subject,
		publicSubject,
		client.ID,
		grantID,
		red.Scope,
		resource,
		now,
		authTime,
		binding,
		nil,
		accessTokenOverrides{ChainID: chainID, ACR: red.ACR},
	)
	if err != nil {
		return preparedPolledResponse{}, err
	}
	if oidcscope.ContainsOpenID(red.Scope) {
		idToken, err = mintPolledIDToken(deps, polledIDTokenInput{
			Subject:     publicSubject,
			ClientID:    client.ID,
			AccessToken: accessToken,
			Now:         now,
			AuthTime:    authTime,
			ACR:         red.ACR,
			Extra:       idTokenExtraClaims(deps, user, red.Scope, nil),
		})
		if err != nil {
			return preparedPolledResponse{}, err
		}
		idToken, err = maybeEncryptIDToken(ctx, deps, client, idToken)
		if err != nil {
			return preparedPolledResponse{}, err
		}
	}
	refreshIn := builtinRefreshIssuance(deps, client)
	refreshIn.Subject = red.Subject
	refreshIn.GrantID = grantID
	refreshIn.Scope = red.Scope
	refreshIn.Resource = resource
	refreshIn.Binding = binding
	refreshIn.Origin = opt.Origin
	refreshIn.ChainID = chainID
	refreshIn.AuthCtx = authContext{AuthTime: authTime, ACR: red.ACR}
	refreshToken, err = issueRefreshToken(ctx, deps, refreshIn)
	if err != nil {
		return preparedPolledResponse{}, err
	}
	return preparedPolledResponse{
		response: successResponse{
			AccessToken:  accessToken,
			TokenType:    binding.tokenTypeFor(),
			ExpiresIn:    int64(deps.AccessTokenTTL.Seconds()),
			RefreshToken: refreshToken,
			IDToken:      idToken,
			Scope:        joinScope(red.Scope),
			GrantID:      grantIDForResponse(deps, grantID),
		},
		opaque:         format == store.AccessTokenFormatOpaque,
		grantID:        grantID,
		discardOnClean: opt.DiscardGrantOnFailure,
	}, nil
}

// polledIDTokenInput collects the parameters [mintPolledIDToken] needs.
type polledIDTokenInput struct {
	Subject     string
	ClientID    string
	AccessToken string
	Now         time.Time
	AuthTime    int64
	ACR         string
	Extra       map[string]any
}

// mintPolledIDToken signs the id_token of a polling-grant redemption.
// at_hash binds the access token minted in the same redemption (OIDC Core
// §3.1.3.6); c_hash and nonce are absent because neither flow has an
// authorization code or a retained nonce.
func mintPolledIDToken(deps Deps, in polledIDTokenInput) (string, error) {
	key := activeSigningKey(deps)
	atHash, err := tokens.HashForAlg(in.AccessToken, key.Alg)
	if err != nil {
		return "", err
	}
	claims := deps.idTokenClaims(in.Subject, in.ClientID, in.Now)
	claims.AtHash = atHash
	claims.AuthTime = in.AuthTime
	claims.ACR = in.ACR
	claims.Extra = in.Extra
	return tokens.SignIDToken(key, claims)
}

// resourceOf returns the single audience a token request resolved to, or
// empty when none was registered; the request gates reject multi-resource
// requests, so at most one entry is present.
func resourceOf(audience []string) string {
	if len(audience) == 0 {
		return ""
	}
	return audience[0]
}

// accessTokenFormat resolves the access-token format for resource.
func accessTokenFormat(deps Deps, resource string) store.AccessTokenFormat {
	if deps.AccessTokenFormatFor != nil {
		return deps.AccessTokenFormatFor(resource)
	}
	return store.AccessTokenFormatJWT
}

// derefTime returns the dereferenced value of t, or the zero time when t is
// nil. The stores expose LastPolledAt as a pointer so "never polled" stays
// distinct from "polled at the epoch"; the poll decision takes a flat time.
func derefTime(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}

// rollbackPolledResponse undoes the credentials a failed
// [preparePolledResponse] already minted and, when opt asks for it, the
// grant it wrote.
func rollbackPolledResponse(
	ctx context.Context,
	deps Deps,
	opt polledIssuance,
	grantID, accessToken, refreshToken string,
	format store.AccessTokenFormat,
) {
	cleanupPreparedCredentials(ctx, deps, accessToken, refreshToken, format == store.AccessTokenFormatOpaque)
	if opt.DiscardGrantOnFailure {
		discardGrant(ctx, deps, grantID)
	}
}
