package tokenendpoint

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/internal/grants/authcode"
	"github.com/libraz/go-oidc-provider/internal/grants/refresh"
	"github.com/libraz/go-oidc-provider/internal/pkce"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
)

// handleAuthorizationCode implements the "grant_type=authorization_code"
// branch of RFC 6749 §4.1.3 and OIDC Core 1.0 §3.1.3.3. The function is a
// thin orchestration: client authentication, code exchange via
// [authcode.Exchanger], and token minting. Decomposing into named helpers
// keeps the cyclomatic complexity well under the project's cap.
func handleAuthorizationCode(w http.ResponseWriter, r *http.Request, deps Deps) {
	ctx := r.Context()
	// DPoP verification runs ahead of client authentication so the
	// `use_dpop_nonce` challenge fires before any client_assertion is
	// consumed. Otherwise the assertion's jti is marked on the first
	// attempt, the nonce-challenged client retries with the same
	// assertion (RFC 9449 §8 contemplates a verbatim retry of the
	// client-side request body), and the OP rejects with
	// invalid_client/ErrAssertionReplayed instead of completing the
	// flow. Reordering is safe because [verifyTokenDPoP] does not
	// depend on the resolved client identity.
	dpopOut, ok := verifyTokenDPoP(w, r, deps)
	if !ok {
		return
	}
	client, _, ok := authenticate(ctx, w, r, deps)
	if !ok {
		return
	}
	in, ok := parseAuthCodeRequest(w, r)
	if !ok {
		return
	}
	in.ClientID = client.ID
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
	exchanged, ok := exchangeAuthCode(ctx, w, deps, in)
	if !ok {
		return
	}
	if !enforcePKCEDowngradeGuard(w, client, exchanged) {
		return
	}
	if !enforceDPoPJKTBinding(w, exchanged, binding) {
		return
	}
	issueAuthCodeResponse(ctx, w, deps, client, in.Code, exchanged, binding)
}

// enforcePKCEDowngradeGuard refuses an authorization_code exchange
// when a public client redeems a code that was issued without a PKCE
// challenge. RFC 9700 §2.1.1 (OAuth 2.0 Security Best Current
// Practice) requires PKCE on every public-client code flow; this
// check is defence-in-depth in case the
// authorize-side gate (which is profile-conditional) was misconfigured
// or bypassed via a forged stored record. Confidential clients are
// free to opt out of PKCE per RFC 6749 §4.1, so the guard scopes to
// [store.Client.PublicClient] and [store.Client.TokenEndpointAuthMethod]
// == "none". The error code is "invalid_grant" because the violation
// is a property of the redeemed grant, not of the request shape.
func enforcePKCEDowngradeGuard(
	w http.ResponseWriter,
	client *store.Client,
	exchanged *authcode.Exchanged,
) bool {
	if exchanged == nil || client == nil {
		return true
	}
	publicClient := client.PublicClient || client.TokenEndpointAuthMethod == "none"
	if !publicClient {
		return true
	}
	if exchanged.HadCodeChallenge {
		return true
	}
	writeError(w, http.StatusBadRequest, errInvalidGrant,
		"PKCE is required for public clients (RFC 9700 §2.1.1)")
	return false
}

// enforceDPoPJKTBinding implements the RFC 9449 §10 contract: when the
// authorization request committed to a DPoP key via the "dpop_jkt"
// parameter, the token endpoint MUST refuse a proof that does not
// match. A non-empty stored thumbprint also requires a proof to be
// presented at all — admitting an unbound token would let an attacker
// who stole the code circumvent the commitment.
//
// When the stored thumbprint is empty the inbound proof's JKT is the
// only binding, so this function is a no-op.
func enforceDPoPJKTBinding(w http.ResponseWriter, exchanged *authcode.Exchanged, binding tokenBinding) bool {
	if exchanged == nil || exchanged.DPoPJKT == "" {
		return true
	}
	if binding.DPoPJKT == "" {
		writeError(w, http.StatusBadRequest, errInvalidGrant,
			"authorization code is bound to a DPoP key but no proof was presented")
		return false
	}
	if binding.DPoPJKT != exchanged.DPoPJKT {
		writeError(w, http.StatusBadRequest, errInvalidGrant,
			"DPoP proof key does not match the dpop_jkt commitment")
		return false
	}
	return true
}

// tokenBinding bundles the sender-constraint fields a token-endpoint
// response inherits from the inbound request. Issuance code threads
// the value through the access-token mint, the id_token mint, and
// the refresh-token persist so the wire shape and the persisted
// record stay in lock-step.
type tokenBinding struct {
	// DPoPJKT is the RFC 7638 thumbprint extracted from a presented
	// DPoP proof. Empty when the request did not carry a proof.
	DPoPJKT string

	// MTLSThumbprint is the RFC 8705 §3.1 thumbprint extracted from
	// a presented client cert. Empty when the request did not
	// terminate mTLS at the OP (or the proxy header path).
	MTLSThumbprint string
}

// refreshDPoPJKT returns the JKT to persist on a refresh-token record
// for the given client. Public clients (TokenEndpointAuthMethod="none")
// MUST have refresh tokens DPoP-bound per RFC 9449 §5.4. Confidential
// clients ([private_key_jwt], [client_secret_*], [tls_client_auth])
// MAY bind or not (RFC 9449 §5.0); the library leaves them unbound so
// the client can rotate its DPoP key across refresh requests, which
// is the OFCS conformance suite's expectation for FAPI 2.0 plans.
//
// The chain remains DPoP-protected at the access-token level: every
// refresh continues to issue a new access token bound to whatever
// DPoP key the client presents on the refresh request, so any holder
// of the access token still needs the matching private key to use it.
func refreshDPoPJKT(client *store.Client, dpopJKT string) string {
	if dpopJKT == "" {
		return ""
	}
	if client != nil && client.TokenEndpointAuthMethod != "none" {
		return ""
	}
	return dpopJKT
}

// confirmation projects the binding onto the cnf claim shape RFC
// 7800 §3 prescribes. An empty binding returns nil so the access-
// token mint can guard the cnf assignment with a non-nil check.
func (b tokenBinding) confirmation() map[string]string {
	switch {
	case b.DPoPJKT != "":
		return map[string]string{"jkt": b.DPoPJKT}
	case b.MTLSThumbprint != "":
		return map[string]string{"x5t#S256": b.MTLSThumbprint}
	default:
		return nil
	}
}

// tokenTypeFor returns the "token_type" wire value: "DPoP" when a DPoP
// proof bound the token, "Bearer" otherwise. RFC 8705 explicitly
// keeps the bearer token_type for cert-bound tokens (§3.1) because
// the binding is on the cnf claim, not the wire token type.
func (b tokenBinding) tokenTypeFor() string {
	if b.DPoPJKT != "" {
		return "DPoP"
	}
	return "Bearer"
}

// constrained reports whether the binding carries either a DPoP
// thumbprint or an mTLS thumbprint. It is the single source of truth
// for the FAPI 2.0 §3.1.4 "sender-constrained tokens MUST be issued"
// check that [enforceSenderConstraint] consults.
func (b tokenBinding) constrained() bool {
	return b.DPoPJKT != "" || b.MTLSThumbprint != ""
}

// enforceSenderConstraint refuses an issuance when the deployment
// requires sender-constrained tokens but the inbound request did not
// present one. It writes the wire error and returns false on the
// reject path; the success path is a no-op true so callers can chain
// it like the other guard helpers in the handler. The error code is
// "invalid_request" because the missing proof is a property of the
// HTTP request shape, not of the credential or the grant: an RP that
// learns of the FAPI policy can fix the problem by re-trying with a
// proof header or a client certificate.
func enforceSenderConstraint(w http.ResponseWriter, deps Deps, b tokenBinding) bool {
	if !deps.RequireSenderConstrainedTokens || b.constrained() {
		return true
	}
	writeError(w, http.StatusBadRequest, errInvalidRequest,
		"sender-constrained access token required: present a DPoP proof or a client certificate")
	return false
}

// authCodeInputs is the de-structured view of the form parameters the
// handler consumes for the authorization_code grant.
type authCodeInputs struct {
	Code         string
	RedirectURI  string
	CodeVerifier string
	ClientID     string
}

// parseAuthCodeRequest validates the required form fields and returns
// them. On failure it writes the response and returns ok=false.
func parseAuthCodeRequest(w http.ResponseWriter, r *http.Request) (authCodeInputs, bool) {
	in := authCodeInputs{
		Code:         r.PostForm.Get("code"),
		RedirectURI:  r.PostForm.Get("redirect_uri"),
		CodeVerifier: r.PostForm.Get("code_verifier"),
	}
	switch {
	case in.Code == "":
		writeError(w, http.StatusBadRequest, errInvalidRequest, "code is required")
		return authCodeInputs{}, false
	case in.RedirectURI == "":
		writeError(w, http.StatusBadRequest, errInvalidRequest, "redirect_uri is required")
		return authCodeInputs{}, false
	}
	// PKCE enforcement is profile-conditional: when the issued code
	// carries a code_challenge, [authcode.Exchanger.Exchange] verifies
	// the presented code_verifier and surfaces ErrVerifierMismatch /
	// ErrVerifierFormat. When it does not, Exchange refuses any
	// supplied verifier (downgrade guard). Letting an empty verifier
	// fall through here lets a non-PKCE code redeem against the
	// authorize policy that issued it; the gate cannot be lifted at
	// /token because the token endpoint does not know the active
	// profile. The complementary defence-in-depth check —
	// [enforcePKCEDowngradeGuard] — runs after Exchange and rejects
	// public-client codes that lack a challenge (RFC 9700 §2.1.1)
	// regardless of whether a verifier was supplied.
	return in, true
}

// exchangeAuthCode runs the [authcode.Exchanger] and translates sentinel
// errors into the wire form. Returns ok=false when a response has
// already been written.
func exchangeAuthCode(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	in authCodeInputs,
) (*authcode.Exchanged, bool) {
	exchanger, err := authcode.NewExchanger(authcode.ExchangerConfig{
		Store: deps.Codes,
		Clock: deps.clockFunc(),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, errServerError, "")
		return nil, false
	}
	exchanged, err := exchanger.Exchange(ctx, authcode.ExchangeInput{
		Code:         in.Code,
		ClientID:     in.ClientID,
		RedirectURI:  in.RedirectURI,
		CodeVerifier: in.CodeVerifier,
	})
	if err != nil {
		writeAuthCodeExchangeError(ctx, w, deps, in.Code, err)
		return nil, false
	}
	return exchanged, true
}

// writeAuthCodeExchangeError maps the sentinels surfaced by
// [authcode.Exchanger] onto wire codes. When the error is a code replay
// the handler additionally walks any descendant refresh tokens and
// revokes them; the walk is best-effort because the token endpoint
// still owes the caller invalid_grant regardless of the bookkeeping
// outcome.
func writeAuthCodeExchangeError(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	code string,
	err error,
) {
	switch {
	case errors.Is(err, authcode.ErrCodeMissing),
		errors.Is(err, authcode.ErrCodeExpired),
		errors.Is(err, authcode.ErrClientMismatch),
		errors.Is(err, authcode.ErrRedirectURIMismatch):
		writeError(w, http.StatusBadRequest, errInvalidGrant, "authorization code rejected")
	case errors.Is(err, authcode.ErrCodeReplayed):
		// §A.12.4: a replayed code is treated as evidence that the
		// chain is compromised. Revoke every refresh token descended
		// from the same grant before responding.
		revokeChainForCode(ctx, deps, code)
		writeError(w, http.StatusBadRequest, errInvalidGrant, "authorization code rejected")
	case errors.Is(err, pkce.ErrChallengeMethodUnsupported),
		errors.Is(err, pkce.ErrVerifierFormat),
		errors.Is(err, pkce.ErrVerifierMismatch):
		writeError(w, http.StatusBadRequest, errInvalidGrant, "PKCE verification failed")
	default:
		writeError(w, http.StatusInternalServerError, errServerError, "")
	}
}

// revokeChainForCode revokes every refresh token whose GrantID matches
// the replayed code's grant. RFC 6749 §4.1.2 says that when an
// authorization code is used more than once the AS MUST revoke "all
// tokens previously issued based on that authorization code"; this is
// the implementation of that MUST.
//
// The walk is best-effort: if the consumed authorization-code record
// is no longer findable (e.g. the store garbage-collected it) the
// function returns silently. The caller still emits invalid_grant.
func revokeChainForCode(ctx context.Context, deps Deps, code string) {
	// We cannot reach the grant id from the consumed code (Consume has
	// already returned ErrAlreadyConsumed). Look the record up via
	// Find; some stores still surface consumed rows there for audit.
	rec, err := deps.Codes.Find(ctx, code)
	if err != nil || rec == nil {
		return
	}
	// Revoke access tokens first so the userinfo / introspection paths
	// reject any AT a sibling refresh might mint racing the cascade.
	// AT first, RT second: a refresh-grant racing the revocation can
	// still mint an AT, but that AT also passes through Register which
	// is a fresh row, leaving the next refresh attempt blocked once
	// the RT half of the cascade lands.
	if deps.AccessTokens != nil {
		_, _ = deps.AccessTokens.RevokeByGrant(ctx, rec.GrantID)
	}
	// Mirror the cascade onto the opaque-AT substore (ADR 0024
	// §"Code-replay cascade"). The substore is nil for embedders who
	// stay on the JWT-only default; calling RevokeByGrant on a nil
	// substore would panic, so guard the call. The order is
	// JWT registry → opaque store → refresh chain; each substore is
	// idempotent so the cascade is order-independent, but we keep the
	// symmetric ordering so log lines / tx audit trails stay
	// predictable.
	if deps.OpaqueAccessTokens != nil {
		_, _ = deps.OpaqueAccessTokens.RevokeByGrant(ctx, rec.GrantID)
	}
	// RevokeByGrant walks the refresh-token store by GrantID and stamps
	// every matching record. Implementations are expected to be silent
	// when no record matches (a freshly-replayed code may not have
	// produced a refresh token at all).
	_ = deps.RefreshTokens.RevokeByGrant(ctx, rec.GrantID)
}

// issueAuthCodeResponse mints the access token, optionally a refresh
// token, and the id_token, then writes the success body. The binding
// argument carries the sender-constraint fields (cnf.jkt for DPoP,
// cnf.x5t#S256 for mTLS) extracted from the inbound request; an
// empty binding produces a plain bearer response.
func issueAuthCodeResponse(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	client *store.Client,
	code string,
	exchanged *authcode.Exchanged,
	binding tokenBinding,
) {
	now := deps.now().UTC()
	authCtx := lookupAuthContext(ctx, deps, exchanged.GrantID)
	if err := requireAuthTimeForIDToken(client, exchanged.Scope, authCtx.AuthTime); err != nil {
		writeError(w, http.StatusInternalServerError, errServerError, "required auth_time is unavailable")
		return
	}
	accessToken, err := mintAccessToken(
		ctx,
		deps,
		exchanged.Subject,
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
	var idToken string
	if scopeContainsOpenID(exchanged.Scope) {
		idTokenExtra := projectIDTokenClaims(ctx, deps, exchanged.Subject, authCtx.Claims)
		idToken, err = mintAuthCodeIDToken(deps, mintIDTokenInput{
			Subject:     exchanged.Subject,
			ClientID:    client.ID,
			Nonce:       exchanged.Nonce,
			AccessToken: accessToken,
			Code:        code,
			Now:         now,
			AuthTime:    authCtx.AuthTime,
			ACR:         authCtx.ACR,
			AMR:         authCtx.AMR,
			Extra:       idTokenExtra,
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, errServerError, "")
			return
		}
	}
	refreshToken, err := maybeIssueRefreshToken(
		ctx,
		deps,
		client,
		exchanged.Subject,
		exchanged.GrantID,
		exchanged.Scope,
		exchanged.Resource,
		binding,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, errServerError, "")
		return
	}
	writeSuccess(w, successResponse{
		AccessToken:  accessToken,
		TokenType:    binding.tokenTypeFor(),
		ExpiresIn:    int64(deps.AccessTokenTTL.Seconds()),
		RefreshToken: refreshToken,
		IDToken:      idToken,
		Scope:        joinScope(exchanged.Scope),
	})
}

// mintIDTokenInput collects the parameters [mintAuthCodeIDToken] needs.
// The struct exists so the function stays under the linter's parameter
// limit.
type mintIDTokenInput struct {
	Subject     string
	ClientID    string
	Nonce       string
	AccessToken string
	Code        string
	Now         time.Time
	AuthTime    int64
	ACR         string
	AMR         []string

	// Extra is the projected non-standard claim set assembled from the
	// grant's persisted OIDC Core 1.0 §5.5 "claims" payload (id_token
	// location). Empty / nil leaves the encoded JWT free of additions
	// beyond the standard fields. Standard-claim collisions are
	// rejected by [tokens.SignIDToken].
	Extra map[string]any
}

// mintAccessToken issues an access token in the wire format the
// configured policy (ADR 0024) selects for the request's RFC 8707
// resource indicator. The function is a thin format-dispatch shim:
// [store.AccessTokenFormatJWT] routes through [mintJWTAccessToken]
// (RFC 9068) and [store.AccessTokenFormatOpaque] routes through
// [mintOpaqueAccessToken] (32-byte random + hashed shadow row). The
// caller threads the same binding / TTL / scope / audience metadata
// regardless of format so refresh-token rotations and the
// /token-success response stay format-agnostic.
//
// grantID is empty for grants without an authorize-side record
// (client_credentials synthesises one upstream so the cascade still
// works); the JWT registry stores the empty string verbatim and
// RevokeByGrant treats the empty grant as a no-op. The opaque path
// stores the same empty string on the row's GrantID column.
func mintAccessToken(
	ctx context.Context,
	deps Deps,
	subject, clientID, grantID string,
	scope []string,
	resource string,
	now time.Time,
	authTime int64,
	binding tokenBinding,
) (string, error) {
	format := store.AccessTokenFormatJWT
	if deps.AccessTokenFormatFor != nil {
		format = deps.AccessTokenFormatFor(resource)
	}
	switch format {
	case store.AccessTokenFormatOpaque:
		return mintOpaqueAccessToken(ctx, deps, subject, clientID, grantID, scope, resource, now, authTime, binding)
	case store.AccessTokenFormatJWT:
		fallthrough
	default:
		return mintJWTAccessToken(ctx, deps, subject, clientID, grantID, scope, resource, now, authTime, binding)
	}
}

// mintJWTAccessToken signs the JWT-shaped access token (RFC 9068) and,
// when the configured registry is non-nil, registers a matching shadow
// row so the userinfo / introspection / revocation paths can reject
// the token after a future revocation (RFC 6749 §4.1.2).
// When the binding carries a DPoP JKT (RFC 9449 §6) or an mTLS
// thumbprint (RFC 8705 §3.1) the token is sender-constrained: the
// "cnf" claim carries the corresponding member ("jkt" or "x5t#S256")
// and the resource server is expected to verify a matching proof on
// every use of the token.
func mintJWTAccessToken(
	ctx context.Context,
	deps Deps,
	subject, clientID, grantID string,
	scope []string,
	resource string,
	now time.Time,
	authTime int64,
	binding tokenBinding,
) (string, error) {
	jti, err := newJTI()
	if err != nil {
		return "", err
	}
	expiresAt := tokens.ExpiresIn(now, deps.AccessTokenTTL)
	audience := deps.Issuer
	if resource != "" {
		audience = resource
	}
	claims := tokens.AccessTokenClaims{
		Issuer:       deps.Issuer,
		Subject:      subject,
		Audience:     []string{audience},
		ClientID:     clientID,
		IssuedAt:     now.Unix(),
		ExpiresAt:    expiresAt,
		JTI:          jti,
		Scope:        append([]string(nil), scope...),
		AuthTime:     authTime,
		Confirmation: binding.confirmation(),
	}
	signed, err := tokens.SignAccessToken(activeSigningKey(deps), claims)
	if err != nil {
		return "", err
	}
	if deps.AccessTokens != nil {
		if err := deps.AccessTokens.Register(ctx, store.AccessTokenRecord{
			JTI:       jti,
			GrantID:   grantID,
			Subject:   subject,
			ClientID:  clientID,
			Scopes:    append([]string(nil), scope...),
			IssuedAt:  now,
			ExpiresAt: time.Unix(expiresAt, 0).UTC(),
		}); err != nil {
			return "", err
		}
	}
	return signed, nil
}

// mintOpaqueAccessToken mints a 32-byte random opaque access token
// (ADR 0024) and persists a matching shadow row so verification at the
// boundaries the OP serves (userinfo, introspection, revocation) has
// the metadata it needs to project. The wire bytes carry no claims;
// the row carries every field the JWT path encodes so introspection
// can return RFC 7662 §2.2 metadata and the cnf thumbprint stays
// re-verifiable on every use.
//
// authTime == 0 (e.g. client_credentials, which has no end-user
// authentication) maps to the row's zero-valued AuthTime so the
// introspection / userinfo paths can omit auth_time uniformly.
func mintOpaqueAccessToken(
	ctx context.Context,
	deps Deps,
	subject, clientID, grantID string,
	scope []string,
	resource string,
	now time.Time,
	authTime int64,
	binding tokenBinding,
) (string, error) {
	if deps.OpaqueAccessTokens == nil {
		// The op.New validator rejects this configuration at
		// construction time, so reaching it here means a manual
		// Deps was misconfigured. Fail the request with server_error
		// rather than minting a credential we cannot persist.
		return "", errors.New("tokenendpoint: opaque format requested but OpaqueAccessTokens substore is nil")
	}
	raw, err := tokens.MintOpaqueAccessToken()
	if err != nil {
		return "", err
	}
	expiresAt := tokens.ExpiresIn(now, deps.AccessTokenTTL)
	audience := deps.Issuer
	if resource != "" {
		audience = resource
	}
	rec := &store.OpaqueAccessToken{
		ID:                 raw,
		GrantID:            grantID,
		Subject:            subject,
		ClientID:           clientID,
		Scope:              append([]string(nil), scope...),
		Audience:           audience,
		AuthTime:           opaqueAuthTime(authTime),
		DPoPJKT:            binding.DPoPJKT,
		MTLSCertThumbprint: binding.MTLSThumbprint,
		IssuedAt:           now,
		ExpiresAt:          time.Unix(expiresAt, 0).UTC(),
	}
	if err := deps.OpaqueAccessTokens.Save(ctx, rec); err != nil {
		return "", err
	}
	return raw, nil
}

// opaqueAuthTime projects the int64 Unix-second auth_time the issuance
// helpers thread through onto the [time.Time]-shaped column the
// [store.OpaqueAccessToken] schema carries. Zero (no end-user
// authentication, e.g. client_credentials) maps to the zero time so
// downstream verifiers can detect "absent" with a single
// [time.Time.IsZero] check.
func opaqueAuthTime(authTime int64) time.Time {
	if authTime == 0 {
		return time.Time{}
	}
	return time.Unix(authTime, 0).UTC()
}

// mintAuthCodeIDToken signs the OIDC id_token issued in response to an
// authorization_code exchange. at_hash and c_hash are populated per
// OIDC Core §3.1.3.6 / §3.3.2.10 because the code-flow id_token is the
// one that benefits the most from the binding.
func mintAuthCodeIDToken(deps Deps, in mintIDTokenInput) (string, error) {
	claims := tokens.IDTokenClaims{
		Issuer:    deps.Issuer,
		Subject:   in.Subject,
		Audience:  []string{in.ClientID},
		IssuedAt:  in.Now.Unix(),
		ExpiresAt: tokens.ExpiresIn(in.Now, deps.IDTokenTTL),
		AuthTime:  in.AuthTime,
		Nonce:     in.Nonce,
		AtHash:    tokens.Hash(in.AccessToken),
		CHash:     tokens.Hash(in.Code),
		ACR:       in.ACR,
		AMR:       append([]string(nil), in.AMR...),
		Extra:     in.Extra,
	}
	return tokens.SignIDToken(activeSigningKey(deps), claims)
}

// maybeIssueRefreshToken issues and persists a refresh token when the
// client and granted scope satisfy [clientPermitsRefresh]. Returns the
// empty string when no refresh token is issued; that is a valid
// successful response (e.g. a non-OIDC client or a public client that
// did not request "openid"). The binding is propagated onto the
// persisted record so refresh-time enforcement can require a
// matching proof / cert.
func maybeIssueRefreshToken(
	ctx context.Context,
	deps Deps,
	client *store.Client,
	subject, grantID string,
	scope []string,
	resource string,
	binding tokenBinding,
) (string, error) {
	if !clientPermitsRefresh(client, scope) {
		return "", nil
	}
	issuer, err := refresh.NewIssuer(refresh.IssuerConfig{
		Store: deps.RefreshTokens,
		Clock: deps.clockFunc(),
		TTL:   pickRefreshTokenTTL(deps, scope),
	})
	if err != nil {
		return "", err
	}
	token, err := issuer.Issue(ctx, refresh.IssueInput{
		ClientID:           client.ID,
		Subject:            subject,
		GrantID:            grantID,
		Scope:              append([]string(nil), scope...),
		Resource:           resource,
		DPoPJKT:            refreshDPoPJKT(client, binding.DPoPJKT),
		MTLSCertThumbprint: binding.MTLSThumbprint,
	})
	if err != nil {
		return "", err
	}
	deps.audit().Emit(ctx, audit.Event{
		Name:     auditTokenIssued,
		Level:    audit.LevelInfo,
		Message:  "refresh token issued",
		ActorID:  subject,
		ClientID: client.ID,
		Extras: map[string]any{
			"grant_id":       grantID,
			"offline_access": scopeContainsOfflineAccess(scope),
			"ttl_bucket":     ttlBucketFor(deps, scope),
		},
	})
	return token, nil
}

func requireAuthTimeForIDToken(client *store.Client, scope []string, authTime int64) error {
	if client == nil || !client.RequireAuthTime || !scopeContainsOpenID(scope) {
		return nil
	}
	if authTime != 0 {
		return nil
	}
	return errors.New("tokenendpoint: require_auth_time cannot be satisfied")
}

// authContext captures the fields the id_token issuance path reads
// from the originating grant. Empty values are valid: the encoder
// omits omitempty claims when the relevant field is zero.
type authContext struct {
	AuthTime int64
	ACR      string
	AMR      []string

	// Claims is the OIDC Core 1.0 §5.5 "claims" request payload that
	// was persisted on the grant at the originating /authorize
	// request. Nil when the request did not carry the parameter.
	// The id_token issuer reads it (along with the user store) to
	// project the requested id_token claims.
	Claims *authorize.ClaimsRequest
}

// lookupAuthContext resolves the auth_time / acr / amr claims from
// the originating grant. The grant carries the values stamped at the
// last interactive authentication; OIDC Core 1.0 §12 requires the
// refresh-token-derived id_token to carry the same acr/amr as the
// original, and the authorization_code-derived id_token uses the same
// source so both grant paths agree. AuthTime falls back to the grant's
// UpdatedAt when the explicit field was not populated (records
// persisted before the field was added still produce a useful claim).
func lookupAuthContext(ctx context.Context, deps Deps, grantID string) authContext {
	if grantID == "" {
		return authContext{}
	}
	g, err := deps.Grants.Find(ctx, grantID)
	if err != nil || g == nil {
		return authContext{}
	}
	out := authContext{ACR: g.ACR}
	if !g.AuthTime.IsZero() {
		out.AuthTime = g.AuthTime.Unix()
	} else if !g.UpdatedAt.IsZero() {
		out.AuthTime = g.UpdatedAt.Unix()
	}
	if len(g.AMR) > 0 {
		out.AMR = append([]string(nil), g.AMR...)
	}
	out.Claims = authorize.DecodeClaimsFromGrant(g.Claims)
	return out
}

// projectIDTokenClaims walks the grant's id_token "claims" payload
// (OIDC Core 1.0 §5.5) and returns the non-standard claims map the
// id_token issuer feeds into [tokens.IDTokenClaims.Extra]. The user
// store is the source of truth for values; claims with no stored
// value or that fail the spec's "value" / "values" constraint are
// silently omitted, matching the project's "omit on absent" stance.
//
// The function returns nil for an empty request, no user lookup, or a
// nil deps.UserStore so the caller can guard the Extra assignment
// with a simple non-nil check.
func projectIDTokenClaims(
	ctx context.Context,
	deps Deps,
	subject string,
	req *authorize.ClaimsRequest,
) map[string]any {
	if req == nil || len(req.IDToken) == 0 {
		return nil
	}
	if deps.UserStore == nil || subject == "" {
		return nil
	}
	user, err := deps.UserStore.FindBySubject(ctx, subject)
	if err != nil || user == nil {
		return nil
	}
	out := map[string]any{}
	for name, spec := range req.IDToken {
		switch name {
		case "sub", "iss", "aud", "iat", "exp", "auth_time", "nonce",
			"acr", "amr", "azp", "at_hash", "c_hash", "sid":
			// Standard id_token claims are issued by the library
			// itself; the projector never overwrites them. The
			// "acr" claim in particular is delegated to the
			// ACR policy seam; here we ignore it.
			continue
		}
		v, ok := user.Claims[name]
		if !ok {
			continue
		}
		if !spec.Allows(v) {
			continue
		}
		out[name] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
