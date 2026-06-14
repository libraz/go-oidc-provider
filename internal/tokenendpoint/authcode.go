package tokenendpoint

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/internal/grants/authcode"
	"github.com/libraz/go-oidc-provider/internal/grants/refresh"
	"github.com/libraz/go-oidc-provider/internal/oidcscope"
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
	authorizationDetails, ok := parseTokenAuthorizationDetails(w, r, deps, client)
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
	if !checkTokenScopeAllowlist(w, deps, client.ID, exchanged.Scope) {
		return
	}
	if !enforcePKCEDowngradeGuard(w, client, exchanged) {
		return
	}
	if !enforceDPoPJKTBinding(w, exchanged, binding) {
		return
	}
	issueAuthCodeResponse(ctx, w, deps, client, in.Code, exchanged, binding, authorizationDetails)
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
	deps.audit().Emit(ctx, audit.Event{
		Name:     auditCodeConsumed,
		Level:    audit.LevelInfo,
		Message:  "authorization code consumed",
		ActorID:  exchanged.Subject,
		ClientID: in.ClientID,
		Extras: map[string]any{
			"code_id":     in.Code,
			"grant_id":    exchanged.GrantID,
			"scope":       append([]string(nil), exchanged.Scope...),
			"consumed_at": exchanged.ConsumedAt,
		},
	})
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
		emitCodeReplayDetected(ctx, deps, authcode.ReplayGrantID(err))
		revokeChainForCode(ctx, deps, code, authcode.ReplayGrantID(err))
		writeError(w, http.StatusBadRequest, errInvalidGrant, "authorization code rejected")
	case errors.Is(err, pkce.ErrChallengeMethodUnsupported),
		errors.Is(err, pkce.ErrVerifierFormat),
		errors.Is(err, pkce.ErrVerifierMismatch):
		writeError(w, http.StatusBadRequest, errInvalidGrant, "PKCE verification failed")
	default:
		writeError(w, http.StatusInternalServerError, errServerError, "")
	}
}

func emitCodeReplayDetected(ctx context.Context, deps Deps, grantID string) {
	deps.audit().Emit(ctx, audit.Event{
		Name:    auditCodeReplayDetected,
		Level:   audit.LevelWarn,
		Message: "authorization-code replay detected",
		Extras: map[string]any{
			"grant_id": grantID,
		},
	})
}

// revokeChainForCode revokes every refresh token whose GrantID matches
// the replayed code's grant. RFC 6749 §4.1.2 says that when an
// authorization code is used more than once the AS MUST revoke "all
// tokens previously issued based on that authorization code"; this is
// the implementation of that MUST.
//
// The JWT-AT half of the cascade dispatches on
// [Deps.RevocationStrategy] (ADR 0025):
//
//   - [store.RevocationStrategyJTIRegistry] flips Revoked on every per-AT
//     shadow row keyed by GrantID (the ADR 0013 model: O(N) writes per
//     cascade where N is the number of live ATs under the grant).
//   - [store.RevocationStrategyGrantTombstone] writes a single
//     [store.GrantTombstone] keyed on GrantID. Verifiers consult the
//     tombstone via the AT's "gid" private claim and reject the token
//     when "iat <= RevokedAt"; the cascade therefore covers every live
//     AT under the grant in O(1) writes.
//   - [store.RevocationStrategyNone] skips the JWT-AT cascade entirely.
//     JWT ATs minted before the cascade live until exp; the embedder
//     opted out of server-side JWT revocation by selecting this
//     strategy.
//
// The opaque-AT cascade and the refresh-token cascade run in all three
// branches: the opaque-AT path is intrinsically per-token and the
// refresh-token cascade is always required to satisfy RFC 6749
// §4.1.2.
//
// The walk is best-effort: replayGrantID is preferred because some stores hide
// consumed rows from Find. For older stores that only expose consumed rows via
// Find, the function falls back to looking the code up before returning.
func revokeChainForCode(ctx context.Context, deps Deps, code, replayGrantID string) {
	grantID := replayGrantID
	if grantID == "" {
		rec, err := deps.Codes.Find(ctx, code)
		if err != nil || rec == nil {
			return
		}
		grantID = rec.GrantID
	}
	if grantID == "" {
		return
	}
	// Revoke access tokens first so the userinfo / introspection paths
	// reject any AT a sibling refresh might mint racing the cascade.
	// AT first, RT second: a refresh-grant racing the revocation can
	// still mint an AT, but the mint-refusal check on the refresh path
	// (under RevocationStrategyGrantTombstone) closes that window, and
	// under RevocationStrategyJTIRegistry the AT also passes through
	// Register which is a fresh row, leaving the next refresh attempt
	// blocked once the RT half of the cascade lands.
	revokeJWTAccessTokensForGrant(ctx, deps, grantID)
	// Mirror the cascade onto the opaque-AT substore (ADR 0024
	// §"Code-replay cascade"). The substore is nil for embedders who
	// stay on the JWT-only default; calling RevokeByGrant on a nil
	// substore would panic, so guard the call. The order is
	// JWT registry → opaque store → refresh chain; each substore is
	// idempotent so the cascade is order-independent, but we keep the
	// symmetric ordering so log lines / tx audit trails stay
	// predictable.
	if deps.OpaqueAccessTokens != nil {
		_, _ = deps.OpaqueAccessTokens.RevokeByGrant(ctx, grantID)
	}
	// RevokeByGrant walks the refresh-token store by GrantID and stamps
	// every matching record. Implementations are expected to be silent
	// when no record matches (a freshly-replayed code may not have
	// produced a refresh token at all).
	_ = deps.RefreshTokens.RevokeByGrant(ctx, grantID)
}

// revokeJWTAccessTokensForGrant runs the JWT-AT half of the
// code-replay cascade against the configured
// [Deps.RevocationStrategy]. The function is a strategy dispatcher:
//
//   - [store.RevocationStrategyJTIRegistry] preserves the ADR 0013
//     behaviour and flips Revoked on every per-AT shadow row.
//   - [store.RevocationStrategyGrantTombstone] writes a single
//     [store.GrantTombstone] (ADR 0025). The tombstone's RevokedAt is
//     stamped at the wall-clock instant the cascade runs and the
//     ExpiresAt outlives the longest possible JWT AT under the grant
//     (now + AccessTokenTTL + 5m grace) so a verifier consulting
//     IsRevoked rejects every AT issued before the cascade until the
//     tombstone is GC'd.
//   - [store.RevocationStrategyNone] is a no-op; JWT ATs live until exp.
//
// All branches swallow store errors: the caller still emits
// invalid_grant on the replay path, and the next /token request hits
// the same cascade so a transient store fault recovers. Logging the
// failure is the OP's responsibility; the tokenendpoint package does
// not own a slog logger today, so we leave the failure observable
// only through the audit emitter (handled by the caller).
func revokeJWTAccessTokensForGrant(ctx context.Context, deps Deps, grantID string) {
	if err := endpointsupport.RevokeJWTAccessTokensByGrant(ctx, endpointsupport.JWTGrantCascadeOpts{
		AccessTokens:       deps.AccessTokens,
		GrantRevocations:   deps.GrantRevocations,
		RevocationStrategy: deps.RevocationStrategy,
	}, grantID, deps.now().UTC(), deps.AccessTokenTTL+5*time.Minute, "code_replay"); err != nil {
		deps.audit().Emit(ctx, audit.Event{
			Name:    auditTokenRevokeFailed,
			Level:   audit.LevelWarn,
			Message: "access-token revoke cascade failed after authorization-code replay",
			Extras: map[string]any{
				"surface":  "code_replay_jwt_access_tokens",
				"grant_id": grantID,
				"err":      err.Error(),
			},
		})
	}
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
	requestedAuthorizationDetails []map[string]any,
) {
	now := deps.now().UTC()
	authCtx := lookupAuthContext(ctx, deps, exchanged.GrantID)
	if err := requireAuthTimeForIDToken(client, exchanged.Scope, authCtx.AuthTime); err != nil {
		writeError(w, http.StatusInternalServerError, errServerError, "required auth_time is unavailable")
		return
	}
	authorizationDetails, ok := reduceAuthorizationDetails(w, requestedAuthorizationDetails, authCtx.AuthorizationDetails)
	if !ok {
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
		authorizationDetails,
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, errServerError, "")
		return
	}
	var idToken string
	if oidcscope.ContainsOpenID(exchanged.Scope) {
		idTokenExtra := projectIDTokenClaims(ctx, deps, exchanged.Subject, authCtx.Claims)
		idToken, err = mintAuthCodeIDToken(deps, mintIDTokenInput{
			Subject:     publicSubject,
			ClientID:    client.ID,
			Nonce:       exchanged.Nonce,
			AccessToken: accessToken,
			Code:        code,
			Now:         now,
			AuthTime:    authCtx.AuthTime,
			ACR:         authCtx.ACR,
			AMR:         authCtx.AMR,
			Claims:      authCtx.Claims,
			Extra:       idTokenExtra,
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, errServerError, "")
			return
		}
		idToken, err = maybeEncryptIDToken(ctx, deps, client, idToken)
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
		exchanged.Nonce,
		binding,
		store.RefreshOriginAuthCode,
		false,
		authCtx.withAuthorizationDetails(authorizationDetails),
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, errServerError, "")
		return
	}
	if !enforceAuthCodeGrantTombstoneMintRefusal(ctx, w, deps, exchanged.GrantID, exchanged.IssuedAt) {
		if refreshToken != "" {
			_ = deps.RefreshTokens.RevokeByGrant(ctx, exchanged.GrantID)
		}
		return
	}
	writeSuccess(w, successResponse{
		AccessToken:          accessToken,
		TokenType:            binding.tokenTypeFor(),
		ExpiresIn:            int64(deps.AccessTokenTTL.Seconds()),
		RefreshToken:         refreshToken,
		IDToken:              idToken,
		Scope:                joinScope(exchanged.Scope),
		AuthorizationDetails: cloneAuthorizationDetails(authorizationDetails),
		GrantID:              grantIDForResponse(deps, exchanged.GrantID),
	})
}

// enforceAuthCodeGrantTombstoneMintRefusal refuses to mint tokens when the
// grant backing the redeemed authorization code carries an active tombstone.
// issuedAt MUST be the code's issuance instant (its CreatedAt), not the
// redemption clock: the store contract treats a grant as revoked for a token
// iff iat <= RevokedAt, and an authorization code is always issued before its
// grant could be tombstoned. Passing the redemption "now" would make the probe
// pass only when redemption coincided with the revocation instant, silently
// minting an access token and a refresh token on a revoked grant for any
// elapsed time after revocation. This mirrors the refresh path, which probes
// with the consumed token's IssuedAt for the same reason.
func enforceAuthCodeGrantTombstoneMintRefusal(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	grantID string,
	issuedAt time.Time,
) bool {
	if deps.RevocationStrategy != store.RevocationStrategyGrantTombstone {
		return true
	}
	if deps.GrantRevocations == nil || grantID == "" {
		return true
	}
	revoked, err := deps.GrantRevocations.IsRevoked(ctx, grantID, "", issuedAt)
	if err != nil {
		writeError(w, http.StatusInternalServerError, errServerError, "")
		return false
	}
	if revoked {
		writeError(w, http.StatusBadRequest, errInvalidGrant, "authorization code rejected")
		return false
	}
	return true
}

// grantIDForResponse returns grantID for the token response only when the
// Grant Management draft is enabled; otherwise it returns "" so the
// grant_id member is omitted and the non-GM response shape is unchanged.
func grantIDForResponse(deps Deps, grantID string) string {
	if !deps.GrantManagementEnabled {
		return ""
	}
	return grantID
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
	Claims      *authorize.ClaimsRequest

	// Extra is the projected non-standard claim set assembled from the
	// grant's persisted OIDC Core 1.0 §5.5 "claims" payload (id_token
	// location). Empty / nil leaves the encoded JWT free of additions
	// beyond the standard fields. Standard-claim collisions are
	// rejected by [tokens.SignIDToken].
	Extra map[string]any
}

func projectPublicSubject(ctx context.Context, deps Deps, raw string, client *store.Client) (string, error) {
	if deps.SubjectProjector == nil {
		return raw, nil
	}
	projected, err := deps.SubjectProjector(ctx, raw, client)
	if err != nil {
		return "", err
	}
	if projected == "" {
		return "", errors.New("tokenendpoint: SubjectProjector returned empty subject")
	}
	return projected, nil
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
// rawSubject is the OP-internal stable user identifier; publicSubject
// is the per-client value that egress representations ("sub" claim on
// JWT access tokens, introspection response on opaque tokens) MUST
// carry. Callers compute publicSubject via [projectPublicSubject] so
// every "sub" visible to the client / RS matches the id_token "sub"
// (RFC 9068 §3). Stores retain the raw value so userinfo /
// introspection / revocation lookups continue to key on the stable
// internal identifier. For client_credentials and other non-end-user
// grants the two values are identical.
//
// grantID is empty for grants without an authorize-side record
// (client_credentials synthesises one upstream so the cascade still
// works); the JWT registry stores the empty string verbatim and
// RevokeByGrant treats the empty grant as a no-op. The opaque path
// stores the same empty string on the row's GrantID column.
func mintAccessToken(
	ctx context.Context,
	deps Deps,
	rawSubject, publicSubject, clientID, grantID string,
	scope []string,
	resource string,
	now time.Time,
	authTime int64,
	binding tokenBinding,
	authorizationDetails []map[string]any,
	extraClaims ...map[string]any,
) (string, error) {
	format := store.AccessTokenFormatJWT
	if deps.AccessTokenFormatFor != nil {
		format = deps.AccessTokenFormatFor(resource)
	}
	switch format {
	case store.AccessTokenFormatOpaque:
		// The opaque path carries no claims; introspection / userinfo
		// echo authorization_details by reading the grant via the shadow
		// row's GrantID, so the details are not threaded onto the token.
		return mintOpaqueAccessToken(ctx, deps, rawSubject, clientID, grantID, scope, resource, now, authTime, binding)
	case store.AccessTokenFormatJWT:
		fallthrough
	default:
		var extra map[string]any
		if len(extraClaims) > 0 {
			extra = extraClaims[0]
		}
		return mintJWTAccessToken(ctx, deps, rawSubject, publicSubject, clientID, grantID, scope, resource, now, authTime, binding, authorizationDetails, extra)
	}
}

// mintJWTAccessToken signs the JWT-shaped access token (RFC 9068) and,
// when the configured strategy is [store.RevocationStrategyJTIRegistry]
// and the registry is non-nil, registers a matching shadow row so the
// userinfo / introspection / revocation paths can reject the token
// after a future revocation (RFC 6749 §4.1.2).
//
// Under the default [store.RevocationStrategyGrantTombstone] (ADR
// 0025) the issuance path is purely compute-bound: the access token
// carries the originating GrantID in its "gid" private claim and the
// verifier consults the per-grant tombstone substore at use, so no
// shadow row is written here.
//
// Under [store.RevocationStrategyNone] no shadow row is written and
// the verifier skips the revocation check entirely; JWT access tokens
// live until exp.
//
// The "gid" claim is populated unconditionally (RFC 7519 §4.3 private
// claim) so a future strategy switch -- or an embedder whose verifier
// runs ahead of the OP it talks to -- can rely on the claim being
// present. The wire form uses omitempty, so empty grantID values
// (synthetic client_credentials grants that elect not to allocate one)
// remain absent on the wire.
//
// When the binding carries a DPoP JKT (RFC 9449 §6) or an mTLS
// thumbprint (RFC 8705 §3.1) the token is sender-constrained: the
// "cnf" claim carries the corresponding member ("jkt" or "x5t#S256")
// and the resource server is expected to verify a matching proof on
// every use of the token.
func mintJWTAccessToken(
	ctx context.Context,
	deps Deps,
	rawSubject, publicSubject, clientID, grantID string,
	scope []string,
	resource string,
	now time.Time,
	authTime int64,
	binding tokenBinding,
	authorizationDetails []map[string]any,
	extraClaims map[string]any,
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
		Issuer:               deps.Issuer,
		Subject:              publicSubject,
		Audience:             []string{audience},
		ClientID:             clientID,
		IssuedAt:             now.Unix(),
		ExpiresAt:            expiresAt,
		JTI:                  jti,
		Scope:                append([]string(nil), scope...),
		AuthTime:             authTime,
		Confirmation:         binding.confirmation(),
		GrantID:              grantID,
		AuthorizationDetails: authorizationDetails,
		Extra:                cloneClaimsMap(extraClaims),
	}
	signed, err := tokens.SignAccessToken(activeSigningKey(deps), claims)
	if err != nil {
		return "", err
	}
	if deps.RevocationStrategy == store.RevocationStrategyJTIRegistry && deps.AccessTokens != nil {
		if err := deps.AccessTokens.Register(ctx, store.AccessTokenRecord{
			JTI:       jti,
			GrantID:   grantID,
			Subject:   rawSubject,
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

func timeFromUnix(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.Unix(v, 0).UTC()
}

func cloneAuthorizationDetails(in []map[string]any) []map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make([]map[string]any, len(in))
	for i, obj := range in {
		if obj == nil {
			continue
		}
		cp := make(map[string]any, len(obj))
		for k, v := range obj {
			cp[k] = v
		}
		out[i] = cp
	}
	return out
}

func cloneClaimsMap(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// mintAuthCodeIDToken signs the OIDC id_token issued in response to an
// authorization_code exchange. at_hash and c_hash are populated per
// OIDC Core §3.1.3.6 / §3.3.2.10 because the code-flow id_token is the
// one that benefits the most from the binding.
func mintAuthCodeIDToken(deps Deps, in mintIDTokenInput) (string, error) {
	key := activeSigningKey(deps)
	atHash, err := tokens.HashForAlg(in.AccessToken, key.Alg)
	if err != nil {
		return "", err
	}
	cHash, err := tokens.HashForAlg(in.Code, key.Alg)
	if err != nil {
		return "", err
	}
	claims := tokens.IDTokenClaims{
		Issuer:    deps.Issuer,
		Subject:   in.Subject,
		Audience:  []string{in.ClientID},
		IssuedAt:  in.Now.Unix(),
		ExpiresAt: tokens.ExpiresIn(in.Now, deps.IDTokenTTL),
		AuthTime:  in.AuthTime,
		Nonce:     in.Nonce,
		AtHash:    atHash,
		CHash:     cHash,
		ACR:       idTokenACRForClaims(in.ACR, in.Claims),
		AMR:       append([]string(nil), in.AMR...),
		Extra:     in.Extra,
	}
	return tokens.SignIDToken(key, claims)
}

func idTokenACRForClaims(acr string, req *authorize.ClaimsRequest) string {
	spec, ok := req.IDTokenSpec("acr")
	if !ok || !spec.Essential {
		return acr
	}
	if len(spec.Values) == 0 && spec.Value == nil {
		return acr
	}
	if spec.Allows(acr) {
		return acr
	}
	return ""
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
	resource, nonce string,
	binding tokenBinding,
	origin store.RefreshTokenOrigin,
	subjectPublic bool,
	authCtx authContext,
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
		ClientID:             client.ID,
		Subject:              subject,
		GrantID:              grantID,
		Scope:                append([]string(nil), scope...),
		Resource:             resource,
		Origin:               origin,
		SubjectPublic:        subjectPublic,
		AuthTime:             timeFromUnix(authCtx.AuthTime),
		ACR:                  authCtx.ACR,
		AMR:                  append([]string(nil), authCtx.AMR...),
		AuthorizationDetails: cloneAuthorizationDetails(authCtx.AuthorizationDetails),
		Nonce:                nonce,
		DPoPJKT:              refreshDPoPJKT(client, binding.DPoPJKT),
		MTLSCertThumbprint:   binding.MTLSThumbprint,
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
			"offline_access": oidcscope.ContainsOfflineAccess(scope),
			"ttl_bucket":     ttlBucketFor(deps, scope),
		},
	})
	return token, nil
}

func requireAuthTimeForIDToken(client *store.Client, scope []string, authTime int64) error {
	if client == nil || !client.RequireAuthTime || !oidcscope.ContainsOpenID(scope) {
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

	// AuthorizationDetails is the RFC 9396 authorization_details the
	// grant was issued with. The token endpoint echoes it on the
	// response (RFC 9396 §6); a refresh reproduces it from the same
	// grant. Nil when the grant carried none.
	AuthorizationDetails []map[string]any
}

func (c authContext) withAuthorizationDetails(details []map[string]any) authContext {
	c.AuthorizationDetails = details
	return c
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
	out.AuthorizationDetails = g.AuthorizationDetails
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
