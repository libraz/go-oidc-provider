package tokenendpoint

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/authorizationdetails"
	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/clientauth/clientauthhttp"
	"github.com/libraz/go-oidc-provider/internal/clientencjwks"
	"github.com/libraz/go-oidc-provider/internal/customgrant"
	"github.com/libraz/go-oidc-provider/internal/dpop"
	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/internal/httpx"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/mtls"
	"github.com/libraz/go-oidc-provider/internal/oidcscope"
	"github.com/libraz/go-oidc-provider/internal/scoperegistry"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
)

// Audit event names mirrored from the public op.AuditEvent catalogue.
// internal/tokenendpoint cannot import op/, so the strings are
// duplicated and TestAuditEvent_TokenMirror in op/audit_test.go pins
// the values together. auditClientAuthnFailure aliases the canonical
// constant in [clientauthhttp] so the boundary helper and the local
// emission sites cannot drift.
const (
	auditTokenIssued        = "token.issued"
	auditTokenRefreshed     = "token.refreshed"
	auditTokenRevokeFailed  = "token.revoke_failed"
	auditCodeConsumed       = "code.consumed"
	auditCodeReplayDetected = "code.replay_detected"
	auditClientAuthnFailure = clientauthhttp.EventClientAuthnFailure
)

// ttlBucketDefault / ttlBucketOffline name the two refresh-token TTL
// buckets the issuer chooses between. The value rides on audit
// extras so SOC tooling can distinguish a long-lived offline_access
// chain from the conventional rotation cadence without re-reading
// the granted scope set.
const (
	ttlBucketDefault = "default"
	ttlBucketOffline = "offline"
)

// Default token TTLs. These match the existing internal grant defaults
// and are duplicated here so a caller that constructs [Deps] without
// filling the TTL fields gets a sensible response shape without having
// to import the grant packages. The refresh-token default is sourced
// from [timex.RefreshTokenTTLDefault] so the value tracks the canonical
// constant.
const (
	defaultAccessTokenTTL = 5 * time.Minute
	defaultIDTokenTTL     = 10 * time.Minute

	// jtiByteLength is the entropy of the access-token "jti" claim. 16
	// bytes (128 bits) is well above the birthday bound for any single
	// deployment and matches the RFC 9068 §4 guidance.
	jtiByteLength = 16
)

// tokenSingleValuedParams is the closed list of /token form parameters
// RFC 6749 §3.2 forbids from appearing more than once. The list spans
// every grant the dispatcher routes (authorization_code, refresh_token,
// device_code, ciba, client_credentials) plus the credentials the
// shared [clientauth] parser consumes; running the duplicate check
// before grant dispatch closes the wire-shape gap independent of which
// grant the request claims.
//
// "resource" is intentionally absent — RFC 8707 §2 allows the resource
// indicator to repeat — and any unknown form key is silently tolerated
// so a future profile that adds a multi-valued parameter does not have
// to plumb through a separate allow-list.
//
//nolint:gochecknoglobals // closed allow-list, intentional package state.
var tokenSingleValuedParams = []string{
	"grant_type",
	"client_id",
	"client_secret",
	"client_assertion_type",
	"client_assertion",
	"code",
	"redirect_uri",
	"code_verifier",
	"refresh_token",
	"scope",
	"device_code",
	"auth_req_id",
}

// Clock is the package-local view of the wall clock. It mirrors the
// userinfo handler's posture: a structurally-typed interface so a value
// satisfying [github.com/libraz/go-oidc-provider/op.Clock] flows through
// without an explicit adapter, and a nil falls back to the system clock.
type Clock interface {
	Now() time.Time
}

// Deps bundles the runtime dependencies the token endpoint needs. The
// HTTP layer constructs a [Deps] once at startup and passes it to
// [Handler]; the handler is otherwise self-contained.
type Deps struct {
	// Issuer is the OP issuer URL. It is written into the "iss" claim of
	// every issued JWT and MUST match the value advertised in discovery.
	Issuer string

	// Clients is the read-only client registry. The handler looks the
	// authenticated client_id up here before delegating to [authn].
	Clients store.ClientStore

	// Codes is the substore for authorization codes. The handler wires
	// it into an [authcode.Exchanger] on every request.
	Codes store.AuthorizationCodeStore

	// RefreshTokens is the substore for refresh tokens. The handler
	// wires it into both a [refresh.Exchanger] and a [refresh.Issuer].
	RefreshTokens store.RefreshTokenStore

	// Grants is the consent substore. Used for "auth_time" lookups when
	// minting the id_token.
	Grants store.GrantStore

	// UserStore is the read-only end-user lookup the handler consults
	// when projecting the OIDC Core 1.0 §5.5 "claims" request payload
	// onto the id_token. A nil value silently disables
	// the projection — the issued id_token then carries only the
	// standard claims plus the per-grant ACR/AMR/auth_time.
	UserStore store.UserStore

	// SubjectProjector, when non-nil, converts the OP-internal raw
	// subject into the per-client public OIDC "sub" value. The
	// projection is applied at every wire egress so RFC 9068 §3 holds
	// (the JWT access token "sub" matches the id_token "sub") and
	// OIDC Core §8.1 / §5.4 hold (userinfo and id_token surface the
	// same pairwise value to the client):
	//
	//   - id_token "sub": projected on issuance.
	//   - JWT access token "sub" (RFC 9068): projected at mintAccessToken;
	//     the JTI revocation registry shadow row keeps the raw value so
	//     OP-internal revocation lookups remain stable.
	//   - Opaque access-token store row: keeps the raw subject; the
	//     introspection handler re-projects on egress.
	//   - Refresh-token store row: keeps the raw subject; the
	//     introspection handler re-projects on egress.
	//   - Grant and authorization-code records: keep the raw subject so
	//     prompt=none / silent-renew lookups by (subject, client_id)
	//     succeed against the session's user-scoped identifier.
	//
	// The userinfo handler recovers the raw subject by pivoting through
	// the access token's "gid" private claim to the owning grant; that
	// path is the only place the OP needs to invert the projection, and
	// because the projection itself is not invertible (HMAC-style salted
	// generators are the common case) the pivot is the load-bearing
	// recovery mechanism rather than a convenience.
	//
	// client_credentials and custom-grant flows skip projection because
	// the "sub" they carry is the client identifier (or a handler-chosen
	// string), not an end-user subject the pairwise generator is
	// configured for.
	SubjectProjector func(ctx context.Context, raw string, client *store.Client) (string, error)

	// Keys is the active OP keyset. The first entry signs newly-issued
	// JWTs; retiring entries are advertised in JWKS only.
	Keys *keys.Set

	// Clock supplies the current wall-clock reading. A nil Clock falls
	// back to [internal/timex.SystemClock].
	Clock Clock

	// AccessTokenTTL is the lifetime of issued access tokens. Zero or
	// negative falls back to [defaultAccessTokenTTL].
	AccessTokenTTL time.Duration

	// IDTokenTTL is the lifetime of issued id_tokens. Zero or negative
	// falls back to [defaultIDTokenTTL].
	IDTokenTTL time.Duration

	// RefreshTokenTTL is the lifetime of issued refresh tokens. Zero or
	// negative falls back to [timex.RefreshTokenTTLDefault].
	RefreshTokenTTL time.Duration

	// RefreshTokenOfflineTTL is the lifetime applied to refresh tokens
	// issued under the OIDC Core 1.0 §11 "offline_access" scope. Zero
	// defers to [RefreshTokenTTL] so embedders that do not distinguish
	// offline use never see the second knob. The handler picks the
	// offline TTL whenever the granted scope contains "offline_access".
	RefreshTokenOfflineTTL time.Duration

	// RefreshTokenGraceTTL bounds the RFC 9700 §2.2.2 grace window
	// during which a just-rotated refresh token is still accepted.
	// Zero or negative falls back to [refresh.GraceTTLDefault]
	// (currently 60s). The token endpoint forwards this verbatim to
	// [refresh.ExchangerConfig.GraceTTL].
	RefreshTokenGraceTTL time.Duration

	// StrictOfflineAccess flips the refresh-token issuance gate to the
	// strict reading of OIDC Core 1.0 §11. When true, refresh tokens
	// are issued (on authcode exchange) and accepted (on refresh
	// rotation) only when the granted scope contains "offline_access";
	// the gate runs in addition to the existing "openid" + per-client
	// `refresh_token` grant requirement.
	StrictOfflineAccess bool

	// GrantManagementEnabled makes the token response carry the issued
	// grant_id (the Grant Management draft). Off by default so the
	// non-GM response shape is unchanged.
	GrantManagementEnabled bool

	// SecretVerifier verifies confidential-client secrets. A nil value
	// installs the library default ([clientauth.Argon2id]) so deployments
	// that follow the reference posture need not wire one explicitly.
	SecretVerifier clientauth.SecretVerifier

	// AssertionVerifier verifies private_key_jwt assertions. A nil value
	// disables private_key_jwt support: requests that arrive with a
	// "client_assertion" parameter are rejected as invalid_client. Wire
	// an [clientauth.PrivateKeyJWTVerifier] (or a custom implementation) to
	// support the asymmetric authentication path.
	AssertionVerifier clientauth.AssertionVerifier

	// AllowedClientAuthMethods optionally restricts which client
	// authentication methods the endpoint accepts, regardless of the
	// registered client's stored TokenEndpointAuthMethod. Empty means
	// "no restriction"; non-empty means the chosen method must appear
	// in the list or the request fails with invalid_client. The OP
	// wires the slice from the active [profile.Profile] set so
	// FAPI 2.0 §3.1.3 is enforced uniformly across /token, /par,
	// /introspect, and /revoke.
	AllowedClientAuthMethods []clientauth.Method

	// Scopes is the read-only scope registry the handler consults
	// when accepting a refresh-time scope override. A nil value
	// disables only the per-scope AllowedClients allowlist check.
	Scopes *scoperegistry.Registry

	// AuthorizationDetailTypes is the RFC 9396 registry accepted at
	// /token. A non-empty map enables the authorization_details
	// request parameter for client_credentials and for authcode /
	// refresh reductions against the originating grant.
	AuthorizationDetailTypes map[string]authorizationdetails.Validator

	// DPoP is the RFC 9449 proof verifier. A nil value disables DPoP
	// processing entirely: the handler ignores the "DPoP" header,
	// issues bearer tokens, and accepts unbound refresh requests.
	// When non-nil the handler verifies any presented proof, binds
	// the issued access token via cnf.jkt, and (for refresh) enforces
	// the proof against the bound thumbprint of the presented token.
	DPoP *dpop.Verifier

	// DPoPNonces is the RFC 9449 §8 nonce issuer consulted on the
	// `use_dpop_nonce` challenge response. A nil value omits the
	// "DPoP-Nonce" response header on the challenge but the JSON
	// envelope still carries error="use_dpop_nonce" so a debugger can
	// see the gate triggered. The expected wiring is one struct that
	// satisfies both [dpop.NonceVerifier] (consumed by [Deps.DPoP])
	// and [dpop.NonceIssuer] (this field) so issuance and validation
	// share a rotation pipeline.
	DPoPNonces dpop.NonceIssuer

	// MTLS is the RFC 8705 client-certificate verifier. A nil value
	// disables mTLS binding entirely: the handler ignores any
	// presented client cert, issues bearer tokens, and accepts
	// refresh requests without checking a thumbprint. When non-nil
	// AND a cert is presented at issuance, the issued access token
	// carries cnf.x5t#S256 and the persisted refresh token records
	// the same thumbprint so subsequent refreshes are gated on the
	// same cert.
	//
	// When BOTH a DPoP proof and a client certificate are presented at
	// /token, the issued token carries both confirmation members —
	// cnf.jkt (DPoP) and cnf.x5t#S256 (mTLS) — per RFC 7800 §3, which
	// admits a multi-member cnf (see tokenBinding.confirmation). The
	// token_type stays "DPoP" (tokenBinding.tokenTypeFor), and a holder
	// must satisfy whichever binding the verifying party checks.
	// Presenting both is an unusual deployment (mTLS transport plus a
	// DPoP header); the common case carries exactly one member.
	MTLS *mtls.Verifier

	// RequireSenderConstrainedTokens, when true, makes the endpoint
	// refuse to issue an access token unless the inbound request
	// carried either a verifiable DPoP proof or a verifiable client
	// certificate (so the issued cnf claim is non-empty). Empty
	// bindings collapse onto an "invalid_request" wire response so
	// FAPI 2.0 §3.1.4 / product-design §J.7.2 are uniformly enforced
	// across all three grant types. The flag is plumbed by the OP
	// wiring layer when any FAPI2 [profile.Profile] is active; the
	// build-time profile validator already gates DPoP|MTLS feature
	// enable, so a runtime "no proof presented" is the only way to
	// trip this branch.
	RequireSenderConstrainedTokens bool

	// AccessTokens is the [store.AccessTokenRegistry] consulted on
	// every issued access token (RFC 6749 §4.1.2 / RFC 6819 §5.2.1.1
	// code-replay revocation). The handler calls Register from each
	// grant path and RevokeByGrant from the code-replay cascade. A
	// nil value disables the registry entirely: the endpoint reverts
	// to the legacy behaviour where issued
	// access tokens carry no shadow row, code replay revokes only
	// refresh tokens, and userinfo / introspection / revocation
	// cannot reject a token that has not yet expired. The library
	// wires a non-nil registry from the configured [op.Store]; tests
	// that exercise the token endpoint directly may leave it nil to
	// preserve the legacy shape.
	AccessTokens store.AccessTokenRegistry

	// OpaqueAccessTokens is the [store.OpaqueAccessTokenStore] the
	// opaque-format issuance path persists shadow rows in (ADR 0024).
	// A nil value disables the opaque path; combined with a non-nil
	// AccessTokenFormatFor that returns [store.AccessTokenFormatOpaque]
	// for some audience, the issuance call site is expected to fall
	// back onto the JWT path so a partial wiring cannot panic at
	// runtime. The library wires a non-nil substore from the
	// configured [op.Store] only when [op.WithAccessTokenFormat]
	// (or [op.WithAccessTokenFormatPerAudience]) selects opaque; the
	// fail-fast validator at op.New rejects opaque-without-substore
	// configurations.
	OpaqueAccessTokens store.OpaqueAccessTokenStore

	// AccessTokenFormatFor resolves the access-token format the
	// issuance path applies to a request whose RFC 8707 resource
	// indicator is resource (ADR 0024). The empty resource string
	// signals "no resource parameter on the request"; callers pass
	// it through and the function MUST return the global default in
	// that case. A nil function defers to [store.AccessTokenFormatJWT]
	// for every audience so the legacy behaviour (RFC 9068 JWT
	// access tokens) is preserved when the wiring layer omits the
	// dependency.
	AccessTokenFormatFor func(resource string) store.AccessTokenFormat

	// GrantRevocations is the [store.GrantRevocationStore] consulted
	// by the grant-tombstone JWT access-token revocation strategy
	// (ADR 0025). Cascades write a per-grant tombstone here rather
	// than one shadow row per AT under that grant; the issuance path
	// also consults the substore to refuse minting under a
	// tombstoned grant. A nil value disables the substore entirely;
	// the strategy then falls back to whichever legacy behaviour
	// [RevocationStrategy] selects. The library wires a non-nil
	// substore from the configured [op.Store] when the embedder pins
	// [op.RevocationStrategyGrantTombstone] (default).
	GrantRevocations store.GrantRevocationStore

	// RevocationStrategy selects the JWT access-token revocation
	// shape (ADR 0025). The zero value is
	// [store.RevocationStrategyGrantTombstone], which is the
	// documented default; the library wires this from
	// [op.WithAccessTokenRevocationStrategy]. The opaque path
	// (ADR 0024) is unaffected because opaque tokens are
	// intrinsically per-token in storage.
	RevocationStrategy store.AccessTokenRevocationStrategy

	// Audit is the structured audit-event sink. A nil Emitter falls
	// back to [audit.Discard] so the handler can call the emitter
	// unconditionally. The token endpoint emits "token.issued"
	// (authcode-derived refresh token minted) and "token.refreshed"
	// (refresh-token rotation) — both carry an offline_access
	// boolean and a ttl_bucket value in Extras so SOC tooling can
	// distinguish the long-lived OIDC Core 1.0 §11 bucket from the
	// conventional rotation cadence.
	Audit audit.Emitter

	// CustomGrants is the dispatcher the handler consults when the
	// request's grant_type matches none of the built-in cases. A
	// nil value disables the surface entirely; the request is
	// rejected with unsupported_grant_type. The op layer constructs
	// the dispatcher from the [op.WithCustomGrant] registrations
	// at provider build time.
	CustomGrants *customgrant.Dispatcher

	// DeviceCodes is the substore for RFC 8628 device-authorization
	// records. The token-endpoint device_code grant looks records
	// up by device_code, applies the polling discipline, and
	// atomically consumes the row before issuing credentials. A
	// nil value disables the device_code grant entirely: requests
	// arriving with grant_type=urn:ietf:params:oauth:grant-type:
	// device_code are rejected with unsupported_grant_type. The
	// op-layer wiring guards op.WithDeviceCodeGrant against the
	// nil-substore case at construction time so a deployment that
	// opts into the grant cannot reach the runtime nil-check.
	DeviceCodes store.DeviceCodeStore

	// CIBARequests is the substore for OpenID Connect CIBA records.
	// The token-endpoint CIBA grant looks records up by auth_req_id,
	// applies the polling discipline, and atomically consumes the row
	// before issuing credentials. A nil value disables the CIBA grant
	// entirely: requests arriving with grant_type=urn:openid:params:
	// grant-type:ciba are rejected with unsupported_grant_type. The
	// op-layer wiring guards op.WithCIBA against the nil-substore case
	// at construction time so a deployment that opts into the grant
	// cannot reach the runtime nil-check.
	CIBARequests store.CIBARequestStore

	// CIBAMaxPollViolations overrides the strike threshold above which
	// the token endpoint locks a CIBA record by calling Deny with
	// reason "poll_abuse". Zero falls back to the library default
	// ([ciba.MaxPollViolations], currently 5).
	CIBAMaxPollViolations uint8

	// ClientEncJWKs resolves the RP's encryption recipient when the
	// client registered id_token_encrypted_response_alg / _enc. The
	// resolver wraps an issued id_token in a JWE addressed to the
	// RP's `use=enc` key (OIDC Core 1.0 §10.2). A nil value disables
	// outbound id_token encryption.
	ClientEncJWKs *clientencjwks.Resolver
}

// Handler returns the HTTP handler the OP mounts at its token endpoint.
// The returned handler is safe for concurrent use; deps MUST NOT be
// mutated after the call.
func Handler(deps Deps) http.Handler {
	resolved := resolveDeps(deps)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serve(w, r, resolved)
	})
}

// serve is the request-scoped entry point. It validates the request
// shape, parses the form body, dispatches on grant_type, and writes the
// response. Decomposing the body keeps the function under cyclop's
// max-complexity gate while remaining readable.
func serve(w http.ResponseWriter, r *http.Request, deps Deps) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeError(w, http.StatusMethodNotAllowed, errInvalidRequest, "method not allowed")
		return
	}
	if !isFormContent(r.Header.Get("Content-Type")) {
		writeError(w, http.StatusBadRequest, errInvalidRequest,
			"content-type must be application/x-www-form-urlencoded")
		return
	}
	endpointsupport.LimitFormBody(w, r)
	if err := r.ParseForm(); err != nil { //nolint:gosec // body bounded by LimitFormBody above
		writeError(w, http.StatusBadRequest, errInvalidRequest, "malformed form body")
		return
	}
	if name, ok := httpx.FirstDuplicateParameter(r.PostForm, tokenSingleValuedParams); !ok {
		writeError(w, http.StatusBadRequest, errInvalidRequest,
			"parameter "+name+" must not be repeated")
		return
	}
	grantType := r.PostForm.Get("grant_type")
	switch grantType {
	case "":
		writeError(w, http.StatusBadRequest, errInvalidRequest, "grant_type is required")
	case "authorization_code":
		handleAuthorizationCode(w, r, deps)
	case "refresh_token":
		handleRefreshToken(w, r, deps)
	case "client_credentials":
		handleClientCredentials(w, r, deps)
	case "urn:ietf:params:oauth:grant-type:device_code":
		handleDeviceCode(w, r, deps)
	case "urn:openid:params:grant-type:ciba":
		handleCIBA(w, r, deps)
	default:
		if deps.CustomGrants != nil && deps.CustomGrants.HasHandler(grantType) {
			handleCustomGrant(w, r, deps, grantType)
			return
		}
		writeError(w, http.StatusBadRequest, errUnsupportedGrantType,
			"grant_type is not supported")
	}
}

// resolveDeps fills in defaults the caller chose to omit. The returned
// value is a fresh copy; the caller's [Deps] is not mutated.
func resolveDeps(d Deps) Deps {
	if d.AccessTokenTTL <= 0 {
		d.AccessTokenTTL = defaultAccessTokenTTL
	}
	if d.IDTokenTTL <= 0 {
		d.IDTokenTTL = defaultIDTokenTTL
	}
	if d.RefreshTokenTTL <= 0 {
		d.RefreshTokenTTL = timex.RefreshTokenTTLDefault
	}
	if d.SecretVerifier == nil {
		d.SecretVerifier = &clientauth.Argon2id{}
	}
	return d
}

// now returns the wall-clock reading for this request, falling back to
// the system clock when [Deps.Clock] is nil.
func (d *Deps) now() time.Time {
	if d.Clock == nil {
		return timex.SystemClock.Now()
	}
	return d.Clock.Now()
}

// clockFunc adapts [Deps.Clock] to the func()-shaped clock the grant
// packages consume. A nil Clock yields nil so the grant packages fall
// back to their own [timex.SystemClock] default.
func (d *Deps) clockFunc() func() time.Time {
	if d.Clock == nil {
		return nil
	}
	return d.Clock.Now
}

// audit returns the configured audit sink, or a [audit.Discard]
// emitter so call sites can invoke Emit unconditionally.
func (d *Deps) audit() audit.Emitter {
	if d.Audit == nil {
		return audit.Discard()
	}
	return d.Audit
}

// ttlBucketFor returns the audit-extras label naming which TTL
// bucket the refresh token will land in. Reads
// [Deps.RefreshTokenOfflineTTL] alongside the granted scope; an
// embedder that did not configure the offline-specific TTL falls
// onto the default bucket regardless of scope so the audit signal
// matches the actual lifetime applied at issuance.
func ttlBucketFor(deps Deps, scope []string) string {
	if deps.RefreshTokenOfflineTTL > 0 && oidcscope.ContainsOfflineAccess(scope) {
		return ttlBucketOffline
	}
	return ttlBucketDefault
}

// successResponse is the §5.1 token-endpoint response body shared by
// every successful grant. Optional fields (refresh_token, id_token) are
// omitempty so the wire form matches the spec's "MUST/MAY" guidance.
type successResponse struct {
	AccessToken          string           `json:"access_token"`
	TokenType            string           `json:"token_type"`
	ExpiresIn            int64            `json:"expires_in"`
	RefreshToken         string           `json:"refresh_token,omitempty"`
	IDToken              string           `json:"id_token,omitempty"`
	Scope                string           `json:"scope"`
	AuthorizationDetails []map[string]any `json:"authorization_details,omitempty"`
	GrantID              string           `json:"grant_id,omitempty"`
	IssuedTokenType      string           `json:"issued_token_type,omitempty"`
}

// writeSuccess marshals body and writes it with the cache-control and
// content-type headers the token endpoint owes every response.
func writeSuccess(w http.ResponseWriter, body successResponse) {
	w.Header().Set("Pragma", "no-cache")
	// gosec G117 flags the AccessToken field name as "secret-shaped";
	// the field name is required by RFC 6749 §5.1 and the token is the
	// purpose of this response. There is no leak: the value is delivered
	// over TLS to the authenticated client only.
	_ = httpx.WriteJSON(w, http.StatusOK, body)
}

// authenticate resolves the client credentials carried by the request,
// looks the client up in the registry, and verifies the credentials. The
// helper delegates to a per-request [clientauthhttp.Authenticator] so
// the token endpoint shares an identical authentication contract with
// the PAR (and any future) endpoint.
//
// The function emits its own response on every failure path so the
// caller only checks the bool: false means "stop, response written".
// Each failure path also raises a "client_authn.failure" audit event so
// SOC tooling can spot probing for a known client_id even though RFC
// 6749 §5.2 mandates the wire response stays at the generic
// "invalid_client" code.
func authenticate(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	deps Deps,
) (*store.Client, *clientauth.Credentials, bool) {
	authenticator := clientauthhttp.Authenticator{
		Clients:           deps.Clients,
		SecretVerifier:    deps.SecretVerifier,
		AssertionVerifier: deps.AssertionVerifier,
		AllowedMethods:    deps.AllowedClientAuthMethods,
		Audit:             deps.audit(),
		AuditEventName:    auditClientAuthnFailure,
		AuditMessage:      "client authentication failed at token endpoint",
	}
	return authenticator.Authenticate(ctx, w, r)
}

// isFormContent reports whether ct is application/x-www-form-urlencoded.
// Parameters (charset, etc.) are tolerated so the handler accepts the
// shape RP libraries actually send.
func isFormContent(ct string) bool {
	return endpointsupport.IsFormContent(ct)
}

// clientPermitsRefresh reports whether the registered client may
// receive refresh tokens. The lax reading of OIDC Core 1.0 §11 is the
// historical default: a refresh token is issued when "refresh_token"
// is in the client's GrantTypes AND the granted scope includes
// "openid". When strictOfflineAccess is true the gate additionally
// requires "offline_access" in scope, matching the strict reading of
// §11 (opt-in via op.WithStrictOfflineAccess).
func clientPermitsRefresh(c *store.Client, scope []string, strictOfflineAccess bool) bool {
	if !oidcscope.ContainsOpenID(scope) {
		return false
	}
	if strictOfflineAccess && !oidcscope.ContainsOfflineAccess(scope) {
		return false
	}
	for _, g := range c.GrantTypes {
		if g == "refresh_token" {
			return true
		}
	}
	return false
}

// pickRefreshTokenTTL returns the TTL the handler uses for a refresh
// token issued or rotated under the supplied scope. The offline TTL
// applies when the granted scope contains "offline_access" AND the
// embedder configured a non-zero RefreshTokenOfflineTTL. Otherwise
// the handler falls back to RefreshTokenTTL (which itself falls back
// to [timex.RefreshTokenTTLDefault] via resolveDeps).
func pickRefreshTokenTTL(deps Deps, scope []string) time.Duration {
	if deps.RefreshTokenOfflineTTL > 0 && oidcscope.ContainsOfflineAccess(scope) {
		return deps.RefreshTokenOfflineTTL
	}
	return deps.RefreshTokenTTL
}

// activeSigningKey returns the package-local signing key the handler
// uses to mint id_tokens and access tokens. It is recomputed on every
// request because the keyset is immutable per construction; the helper
// exists so the call sites do not duplicate the boundary copy.
func activeSigningKey(deps Deps) tokens.SigningKey {
	return tokens.FromInternalEntry(deps.Keys.Active())
}

// newJTI returns a base64url-no-pad encoded random identifier suitable
// for the "jti" claim of access tokens (RFC 9068 §4). The function
// satisfies the depguard crypto/rand allow-list because internal/grants
// also uses crypto/rand directly; if the allow-list expands later this
// helper can be replaced with a shared utility.
func newJTI() (string, error) {
	buf := make([]byte, jtiByteLength)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("tokenendpoint: read random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// joinScope is the canonical RFC 6749 §3.3 space-delimited form. The
// helper exists so the success-response builder doesn't grow a strings
// import in two places.
func joinScope(scope []string) string {
	return strings.Join(scope, " ")
}
