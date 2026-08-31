package tokenendpoint

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/customgrant"
	tokenexchangegrant "github.com/libraz/go-oidc-provider/internal/customgrant/tokenexchange"
	"github.com/libraz/go-oidc-provider/internal/oidcscope"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
)

// handleCustomGrant routes the request to the dispatcher the OP
// constructed from [op.WithCustomGrant] registrations. Authentication
// runs through the same chain the built-in grants use; DPoP / mTLS
// verification follows the same ordering so a custom grant inherits
// the FAPI 2.0 §3.1.4 sender-constraint posture without per-handler
// boilerplate. The function never mints tokens itself: the handler's
// returned access_token is written verbatim, the dispatcher having
// already enforced TTL / scope / audience invariants.
func handleCustomGrant(w http.ResponseWriter, r *http.Request, deps Deps, grantType string) {
	// Proof verification, client authentication, and the proof's
	// replay marking run in the order [authenticateWithDPoP] documents.
	ctx := r.Context()
	dpopOut, client, ok := authenticateWithDPoP(ctx, w, r, deps, grantType)
	if !ok {
		return
	}
	mtlsOut, ok := verifyTokenMTLS(w, r, deps, dpopOut.JKT)
	if !ok {
		return
	}
	binding := tokenBinding{
		DPoPJKT:        dpopOut.JKT,
		MTLSThumbprint: mtlsOut.Thumbprint,
	}
	if !enforceSenderConstraint(w, deps, binding) {
		return
	}
	// DPoPJKT / DPoPJTI / MTLSCert ride into the dispatcher so the
	// handler can bind the issued access token (cnf.jkt /
	// cnf.x5t#S256) and so its audit emission can correlate the
	// wire request with the verified proof / leaf cert. The OP does
	// not synthesise cnf for handler-supplied access tokens — the
	// dispatcher writes resp.AccessToken verbatim — so a JWT-shape
	// access token MUST embed the binding claims itself, and an
	// opaque-shape access token MUST surface the binding through
	// the handler's own introspection backend.
	dispatchIn := customgrant.DispatchInput{
		GrantType: grantType,
		Client:    client,
		Form:      r.PostForm,
		DPoPJKT:   dpopOut.JKT,
		DPoPJTI:   dpopOut.JTI,
	}
	if mtlsOut.Cert != nil {
		dispatchIn.MTLSCert = mtlsOut.Cert
	}
	resp, err := deps.CustomGrants.Dispatch(ctx, dispatchIn)
	if err != nil {
		writeCustomGrantError(w, err)
		return
	}
	if !checkTokenScopeAllowlist(w, deps, client.ID, resp.Scope) {
		return
	}
	issued, err := issueCustomGrantTokens(ctx, deps, client, dispatchIn, resp, binding)
	if err != nil {
		// Everything past the dispatcher is the OP's own response
		// construction — JWT signing, claim-collision rejection, jti
		// generation, token-store I/O. None of it is a defect of the
		// grant the client presented, so none of it may collapse onto
		// an RFC 6749 §5.2 4xx code: the wire shape must send the
		// embedder to the handler and to the OP's audit record rather
		// than to the client's credentials.
		writeError(w, http.StatusInternalServerError, errServerError, "")
		return
	}
	issuedTokenType := ""
	if grantType == tokenexchangegrant.GrantType {
		issuedTokenType = tokenexchangegrant.TokenTypeAccessToken
	}
	writeSuccess(w, successResponse{
		AccessToken:     issued.AccessToken,
		TokenType:       binding.tokenTypeFor(),
		ExpiresIn:       int64(issued.AccessTokenTTL.Seconds()),
		RefreshToken:    issued.RefreshToken,
		IDToken:         issued.IDToken,
		Scope:           joinScope(resp.Scope),
		IssuedTokenType: issuedTokenType,
	})
}

// customGrantIssued bundles the credentials [issueCustomGrantTokens]
// resolved for one dispatched response.
type customGrantIssued struct {
	AccessToken    string
	AccessTokenTTL time.Duration
	RefreshToken   string
	IDToken        string
}

// issueCustomGrantTokens is the terminal every dispatched custom-grant
// response passes through on its way to the wire. It exists so the
// credentials a custom grant returns are minted by the same code the
// built-in grants use — [mintAccessToken] for the access token,
// [issueRefreshToken] for the refresh chain root,
// [requireAuthTimeForIDToken] before the id_token — instead of by a
// parallel implementation that has to be kept in step with them by
// hand.
//
// Any error is the OP's own failure to construct the response; the
// caller surfaces every one of them as server_error.
func issueCustomGrantTokens(
	ctx context.Context,
	deps Deps,
	client *store.Client,
	in customgrant.DispatchInput,
	resp customgrant.Response,
	binding tokenBinding,
) (customGrantIssued, error) {
	// The OP owns the grant identity: one GrantID is stamped on the
	// access token and shared with any refresh token minted for this
	// response, so the refresh credential rides the same per-grant
	// revocation cascade and rotation chain as the access token.
	grantID, err := newJTI()
	if err != nil {
		return customGrantIssued{}, err
	}
	accessToken, accessTokenTTL, err := resolveCustomGrantAccessToken(ctx, deps, client, in, resp, binding, grantID)
	if err != nil {
		return customGrantIssued{}, err
	}
	refreshToken, err := issueCustomGrantRefresh(ctx, deps, client, resp, grantID, binding)
	if err != nil {
		return customGrantIssued{}, err
	}
	idToken, err := resolveCustomGrantIDToken(deps, client, resp)
	if err != nil {
		return customGrantIssued{}, err
	}
	return customGrantIssued{
		AccessToken:    accessToken,
		AccessTokenTTL: accessTokenTTL,
		RefreshToken:   refreshToken,
		IDToken:        idToken,
	}, nil
}

// issueCustomGrantRefresh mints and persists a refresh token for a
// custom-grant response that asked for one. The OP owns the credential
// (RFC 6749 §6): it generates the value, persists it on the refresh-token
// store under the access token's grantID, and binds it to the request's
// DPoP / mTLS proof so refresh-time enforcement requires a matching
// proof.
//
// The gates are [issueRefreshToken]'s, so a Provider that does not serve
// the refresh_token grant cannot hand out a chain root through a custom
// grant either, and a successful issuance emits the same token.issued
// record as any other grant's. What is specific to this path is the
// disposition of a refusal: the request stated intent the OP declined to
// honour, so every drop is audited as custom_grant.refresh_dropped and
// the rest of the response is still issued. Returns the empty string
// when no refresh token is issued.
//
// The scope predicate the built-in grants apply is deliberately absent:
// delegation-style custom grants (token exchange) legitimately issue
// refresh tokens with no OIDC scope, so the openid / offline_access
// reading of OIDC Core 1.0 §11 does not gate them.
func issueCustomGrantRefresh(
	ctx context.Context,
	deps Deps,
	client *store.Client,
	resp customgrant.Response,
	grantID string,
	binding tokenBinding,
) (string, error) {
	if !resp.IssueRefreshToken {
		return "", nil
	}
	subject := customGrantRefreshSubject(resp)
	in := refreshIssuance{
		Client:           client,
		Subject:          subject,
		SubjectPublic:    true,
		GrantID:          grantID,
		Scope:            resp.Scope,
		Resource:         singleAudienceResource(resp.Audience),
		Origin:           store.RefreshOriginCustomGrant,
		Binding:          binding,
		AuthCtx:          authContext{AuthTime: authTimeUnix(resp.AuthTime)},
		AccessTokenExtra: customGrantAccessTokenExtra(resp),
		OnDrop: func(reason string) {
			deps.audit().Emit(ctx, audit.Event{
				Name:     customgrant.AuditEventRefreshDropped,
				Level:    audit.LevelInfo,
				Message:  customGrantRefreshDropMessage(reason),
				ActorID:  subject,
				ClientID: client.ID,
				Extras:   map[string]any{"reason": reason},
			})
		},
	}
	if len(resp.Audience) > 1 {
		in.Ineligible = refreshDropMultipleResources
	}
	return issueRefreshToken(ctx, deps, in)
}

// customGrantRefreshDropMessage renders the operator-facing message for
// a refresh drop. The reason itself rides on the event's extras; the
// message spells it out for a human reading the audit stream.
func customGrantRefreshDropMessage(reason string) string {
	const prefix = "custom-grant refresh token dropped: "
	switch reason {
	case refreshDropProviderGrantDisabled:
		return prefix + "the refresh_token grant is not enabled on this provider"
	case refreshDropClientNotRegistered:
		return prefix + "client not registered for refresh_token grant"
	case refreshDropMultipleResources:
		return prefix + "response audience contains multiple resources"
	case refreshDropEmptySubject:
		return prefix + "response subject is empty"
	case refreshDropEmptyScope:
		return prefix + "response scope is empty"
	default:
		return prefix + reason
	}
}

func singleAudienceResource(audience []string) string {
	if len(audience) == 1 {
		return audience[0]
	}
	return ""
}

func customGrantAccessTokenExtra(resp customgrant.Response) map[string]any {
	if resp.BoundAccessToken != nil {
		return cloneClaimsMap(resp.BoundAccessToken.ExtraClaims)
	}
	return nil
}

// customGrantRefreshSubject picks the subject persisted on the
// refresh-token record: the response Subject, falling back to the bound
// access token's subject. Empty is permitted for delegation grants.
func customGrantRefreshSubject(resp customgrant.Response) string {
	if resp.Subject != "" {
		return resp.Subject
	}
	if resp.BoundAccessToken != nil {
		return resp.BoundAccessToken.Subject
	}
	return ""
}

// resolveCustomGrantAccessToken returns the access token and its TTL
// for the wire response. The handler-supplied [customgrant.Response.AccessToken]
// passes through verbatim — the OP does not re-mint the value the
// handler signed. When the response carries a [customgrant.BoundAccessToken]
// instead, the OP mints through [mintAccessToken], the same chokepoint
// the four built-in grants use, so the bound token gets the same jti,
// gid, cnf stamping and JTI-registry shadow row they do: cnf.jkt for
// DPoP, cnf.x5t#S256 for mTLS, neither for a plain bearer request.
//
// The mint is pinned to the RFC 9068 JWT shape rather than following
// [Deps.AccessTokenFormatFor]. A bound token's audience is a set and
// its claims are the handler's (the token-exchange act chain among
// them); the opaque shadow row carries one audience column and no
// claim map, so an opaque deployment would hand the resource server a
// token stripped of the delegation record it is supposed to act on.
// The exclusion is documented on op.WithAccessTokenFormat and
// op.BoundAccessToken.
//
// Both paths substitute the OP's configured access-token TTL for an
// unset handler lifetime. A zero TTL means "the handler did not state
// one", not "expire immediately": expires_in is the RFC 6749 §5.1
// lifetime the client uses to decide when to stop presenting the
// credential, so shipping 0 turns an omitted field into a token the
// client discards on arrival.
func resolveCustomGrantAccessToken(
	ctx context.Context,
	deps Deps,
	client *store.Client,
	in customgrant.DispatchInput,
	resp customgrant.Response,
	binding tokenBinding,
	grantID string,
) (string, time.Duration, error) {
	if resp.BoundAccessToken == nil {
		return resp.AccessToken, customGrantTTL(deps, resp.AccessTokenTTL), nil
	}
	subject := customGrantBoundSubject(in, resp)
	if subject == "" {
		return "", 0, customgrant.ErrEmptyBoundSubject
	}
	audience := resp.BoundAccessToken.Audience
	if len(audience) == 0 {
		audience = []string{client.ID}
	}
	ttl := customGrantTTL(deps, resp.BoundAccessToken.TTL)
	// The handler's subject is already the wire value — a custom grant
	// resolves identity itself and the OP does not project it a second
	// time — so the raw and public subjects are the same string.
	//
	// auth_time is deliberately not threaded onto the access token:
	// [customgrant.Response.AuthTime] states when the handler's subject
	// authenticated for the id_token and the refresh record, and RFC
	// 9068 does not ask the access token to carry it.
	signed, err := mintAccessToken(
		ctx,
		deps,
		subject,
		subject,
		client.ID,
		grantID,
		resp.Scope,
		singleAudienceResource(audience),
		deps.now().UTC(),
		0,
		binding,
		nil,
		accessTokenOverrides{
			TTL:      ttl,
			Audience: audience,
			Extra:    resp.BoundAccessToken.ExtraClaims,
			ForceJWT: true,
		},
	)
	if err != nil {
		return "", 0, err
	}
	return signed, ttl, nil
}

// customGrantTTL resolves the lifetime the OP advertises for a
// custom-grant access token. A handler that leaves the lifetime unset
// gets the OP's configured access-token TTL, which is also the ceiling
// the dispatcher truncates any stated lifetime to, so the substituted
// value can never exceed what an explicit TTL would have been allowed
// to request. Negative lifetimes never reach this point: the dispatcher
// rejects them before the wire layer runs.
func customGrantTTL(deps Deps, stated time.Duration) time.Duration {
	if stated > 0 {
		return stated
	}
	return deps.AccessTokenTTL
}

// customGrantBoundSubject picks the "sub" claim for an OP-minted bound
// access token. The handler's most specific statement wins: the bound
// token's own Subject, then the response-level Subject it resolved for
// the grant, then whatever subject the request carried into dispatch.
// The request-level value is last because the token endpoint
// authenticates a client rather than an end user — no custom grant
// reaching this seam has an OP-resolved subject to offer, so the chain
// would otherwise dead-end on a handler that stated its subject once,
// at the response level.
func customGrantBoundSubject(in customgrant.DispatchInput, resp customgrant.Response) string {
	if resp.BoundAccessToken != nil && resp.BoundAccessToken.Subject != "" {
		return resp.BoundAccessToken.Subject
	}
	if resp.Subject != "" {
		return resp.Subject
	}
	return in.SubjectID
}

// resolveCustomGrantIDToken returns the id_token to surface on the wire.
// The handler-supplied [customgrant.Response.IDToken] is preferred and
// passes through verbatim — the embedder may have signed it with an
// out-of-band key (HSM, federated AS) the OP does not know about. When
// the field is empty the OP signs a fresh token from the response
// Subject, AuthTime, and ExtraClaims, but only when the response's
// [customgrant.Response.IssueIDToken] decision permits it AND the
// granted Scope contains "openid": a handler that resolved "no id_token
// for this exchange" has withheld the act chain and the cnf binding
// that belong on it, so emitting one anyway would ship a delegated
// credential laundered of both. An empty Subject on the mint path is a
// handler bug because id_token "sub" is REQUIRED per OIDC Core 1.0 §2.
func resolveCustomGrantIDToken(deps Deps, client *store.Client, resp customgrant.Response) (string, error) {
	if resp.IDToken != "" {
		return resp.IDToken, nil
	}
	if !resp.IssueIDToken || !oidcscope.ContainsOpenID(resp.Scope) {
		return "", nil
	}
	if resp.Subject == "" {
		return "", errors.New("custom_grant: openid-scoped response has empty Subject")
	}
	// The same fail-closed gate the built-in grants run before signing:
	// a client registered with require_auth_time must not receive an
	// id_token whose auth_time claim was silently omitted, because the
	// absence reads as "the session is fresh".
	if err := requireAuthTimeForIDToken(client, resp.Scope, authTimeUnix(resp.AuthTime)); err != nil {
		return "", err
	}
	now := deps.now().UTC()
	claims := tokens.IDTokenClaims{
		Issuer:    deps.Issuer,
		Subject:   resp.Subject,
		Audience:  []string{client.ID},
		IssuedAt:  now.Unix(),
		ExpiresAt: tokens.ExpiresIn(now, deps.IDTokenTTL),
		Extra:     resp.ExtraClaims,
	}
	if !resp.AuthTime.IsZero() {
		claims.AuthTime = resp.AuthTime.Unix()
	}
	return tokens.SignIDToken(activeSigningKey(deps), claims)
}

// writeCustomGrantError translates the dispatcher's typed sentinels
// into the RFC 6749 §5.2 wire envelope. Sentinels the dispatcher
// owns map onto deterministic codes; an upstream *Error returned by
// the handler is propagated verbatim through the [opErrorWriter]
// interface check so a handler that synthesises its own wire shape
// keeps it.
func writeCustomGrantError(w http.ResponseWriter, err error) {
	if hookErr, ok := err.(opErrorWriter); ok {
		hookErr.WriteOAuthError(w)
		return
	}
	switch {
	case errors.Is(err, customgrant.ErrUnknownGrant):
		writeError(w, http.StatusBadRequest, errUnsupportedGrantType,
			"grant_type is not supported")
	case errors.Is(err, customgrant.ErrClientGrantNotPermitted):
		writeError(w, http.StatusBadRequest, errUnauthorizedClient,
			"client is not authorized for this grant_type")
	case errors.Is(err, customgrant.ErrUnknownParameter),
		errors.Is(err, customgrant.ErrDuplicateParameter),
		errors.Is(err, customgrant.ErrDuplicateCapExceeded):
		writeError(w, http.StatusBadRequest, errInvalidRequest,
			sanitizeMessage(err))
	case errors.Is(err, customgrant.ErrScopeNotAllowed):
		writeError(w, http.StatusBadRequest, errInvalidScope,
			"response scope exceeds the client's allowed set")
	case errors.Is(err, customgrant.ErrAudienceNotAllowed):
		writeError(w, http.StatusBadRequest, errInvalidTarget,
			"response audience exceeds the client's registered resources")
	case errors.Is(err, customgrant.ErrEmptyAccessToken),
		errors.Is(err, customgrant.ErrNegativeTTL),
		errors.Is(err, customgrant.ErrPanic),
		errors.Is(err, customgrant.ErrConflictingAccessTokenForms),
		errors.Is(err, customgrant.ErrEmptyBoundSubject):
		writeError(w, http.StatusInternalServerError, errServerError, "")
	default:
		writeError(w, http.StatusBadRequest, errInvalidGrant,
			"the supplied grant could not be honoured")
	}
}

// opErrorWriter is the structural interface a handler-supplied
// error MAY satisfy to pin the wire shape of its rejection. The
// op-side [op.Error] type implements it; a handler that returns
// such an error short-circuits the sentinel translation table.
type opErrorWriter interface {
	WriteOAuthError(w http.ResponseWriter)
}

// sanitizeMessage strips any embedded parameter name from the
// dispatcher's "%w: %q" error format so the wire response carries
// only the failure family. The dispatcher's audit emission keeps
// the original parameter name on the operator-facing record.
func sanitizeMessage(err error) string {
	msg := err.Error()
	if i := strings.Index(msg, ":"); i > 0 {
		return msg[:i]
	}
	return msg
}
