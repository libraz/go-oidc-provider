package tokenendpoint

import (
	"context"
	"errors"
	"net/http"
	"time"

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
	client, _, ok := authenticate(ctx, w, r, deps)
	if !ok {
		return
	}
	in, ok := parseAuthCodeRequest(w, r)
	if !ok {
		return
	}
	in.ClientID = client.ID
	dpopOut, ok := verifyTokenDPoP(w, r, deps)
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
	exchanged, ok := exchangeAuthCode(ctx, w, deps, in)
	if !ok {
		return
	}
	issueAuthCodeResponse(ctx, w, deps, client, in.Code, exchanged, binding)
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
	// profile.
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
	accessToken, err := mintAccessToken(
		deps,
		exchanged.Subject,
		client.ID,
		exchanged.Scope,
		now,
		lookupAuthTime(ctx, deps, exchanged.GrantID),
		binding,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, errServerError, "")
		return
	}
	idToken, err := mintAuthCodeIDToken(deps, mintIDTokenInput{
		Subject:     exchanged.Subject,
		ClientID:    client.ID,
		Nonce:       exchanged.Nonce,
		AccessToken: accessToken,
		Code:        code,
		Now:         now,
		AuthTime:    lookupAuthTime(ctx, deps, exchanged.GrantID),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, errServerError, "")
		return
	}
	refreshToken, err := maybeIssueRefreshToken(ctx, deps, client, exchanged.Subject, exchanged.GrantID, exchanged.Scope, binding)
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
// limit and so future fields (acr / amr) can be added without churning
// every call site.
type mintIDTokenInput struct {
	Subject     string
	ClientID    string
	Nonce       string
	AccessToken string
	Code        string
	Now         time.Time
	AuthTime    int64
}

// mintAccessToken signs the JWT-shaped access token (RFC 9068). When
// the binding carries a DPoP JKT (RFC 9449 §6) or an mTLS thumbprint
// (RFC 8705 §3.1) the token is sender-constrained: the "cnf" claim
// carries the corresponding member ("jkt" or "x5t#S256") and the
// resource server is expected to verify a matching proof on every
// use of the token.
func mintAccessToken(
	deps Deps,
	subject, clientID string,
	scope []string,
	now time.Time,
	authTime int64,
	binding tokenBinding,
) (string, error) {
	jti, err := newJTI()
	if err != nil {
		return "", err
	}
	claims := tokens.AccessTokenClaims{
		Issuer:       deps.Issuer,
		Subject:      subject,
		Audience:     []string{deps.Issuer},
		ClientID:     clientID,
		IssuedAt:     now.Unix(),
		ExpiresAt:    tokens.ExpiresIn(now, deps.AccessTokenTTL),
		JTI:          jti,
		Scope:        append([]string(nil), scope...),
		AuthTime:     authTime,
		Confirmation: binding.confirmation(),
	}
	return tokens.SignAccessToken(activeSigningKey(deps), claims)
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
	binding tokenBinding,
) (string, error) {
	if !clientPermitsRefresh(client, scope) {
		return "", nil
	}
	issuer, err := refresh.NewIssuer(refresh.IssuerConfig{
		Store: deps.RefreshTokens,
		Clock: deps.clockFunc(),
		TTL:   deps.RefreshTokenTTL,
	})
	if err != nil {
		return "", err
	}
	return issuer.Issue(ctx, refresh.IssueInput{
		ClientID:           client.ID,
		Subject:            subject,
		GrantID:            grantID,
		Scope:              append([]string(nil), scope...),
		DPoPJKT:            refreshDPoPJKT(client, binding.DPoPJKT),
		MTLSCertThumbprint: binding.MTLSThumbprint,
	})
}

// lookupAuthTime resolves the "auth_time" claim from the originating
// grant. The library uses [store.Grant.UpdatedAt] as the proxy for the
// last interactive authentication: every consent prompt or re-auth
// touches the grant, so its updated_at advances when the user freshly
// authenticated. Returns 0 when the grant cannot be located so the
// claim is omitted from the id_token.
func lookupAuthTime(ctx context.Context, deps Deps, grantID string) int64 {
	if grantID == "" {
		return 0
	}
	g, err := deps.Grants.Find(ctx, grantID)
	if err != nil || g == nil || g.UpdatedAt.IsZero() {
		return 0
	}
	return g.UpdatedAt.Unix()
}
