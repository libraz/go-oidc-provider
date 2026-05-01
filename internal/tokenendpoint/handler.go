package tokenendpoint

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/dpop"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/mtls"
	"github.com/libraz/go-oidc-provider/internal/scoperegistry"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
)

// Audit event names mirrored from the public op.AuditEvent catalogue.
// internal/tokenendpoint cannot import op/, so the strings are
// duplicated and TestAuditEvent_TokenMirror in op/audit_test.go pins
// the values together.
const (
	auditTokenIssued        = "token.issued"
	auditTokenRefreshed     = "token.refreshed"
	auditClientAuthnFailure = "client_authn.failure"
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
// to import the grant packages.
const (
	defaultAccessTokenTTL  = 5 * time.Minute
	defaultIDTokenTTL      = 10 * time.Minute
	defaultRefreshTokenTTL = 30 * 24 * time.Hour

	// jtiByteLength is the entropy of the access-token "jti" claim. 16
	// bytes (128 bits) is well above the birthday bound for any single
	// deployment and matches the RFC 9068 §4 guidance.
	jtiByteLength = 16

	// scopeOpenID is duplicated here so the handler can decide whether
	// id_tokens are issued without taking a dependency on
	// [internal/userinfo].
	scopeOpenID = "openid"

	// scopeOfflineAccess is the OIDC Core 1.0 §11 token that gates
	// strict-mode refresh-token issuance and selects the offline TTL
	// bucket under the lax-mode default. Duplicated as a literal here
	// for the same dependency-isolation reason as scopeOpenID.
	scopeOfflineAccess = "offline_access"

	// maxFormBytes caps the size of a token-endpoint request body. The
	// endpoint accepts only the form-encoded shape RFC 6749 §3.2
	// describes; a 64 KiB ceiling is far above any legitimate request
	// (the largest field, a private_key_jwt assertion, comfortably fits
	// in a few KiB) while bounding memory use against pathological
	// inputs (gosec G120).
	maxFormBytes = 64 * 1024
)

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
	// negative falls back to [defaultRefreshTokenTTL].
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
	// (currently 30s). The token endpoint forwards this verbatim to
	// [refresh.ExchangerConfig.GraceTTL].
	RefreshTokenGraceTTL time.Duration

	// StrictOfflineAccess flips the refresh-token issuance gate to the
	// strict reading of OIDC Core 1.0 §11. When true, refresh tokens
	// are issued (on authcode exchange) and accepted (on refresh
	// rotation) only when the granted scope contains "offline_access";
	// the gate runs in addition to the existing "openid" + per-client
	// `refresh_token` grant requirement.
	StrictOfflineAccess bool

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
	// DPoP and MTLS are mutually exclusive on a single token: when
	// both are presented at /token the handler prefers DPoP (cnf.jkt)
	// and skips the mTLS binding so the wire shape stays
	// unambiguous.
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
	//
	// Wave 2 plumbs this field; the handler logic that consumes it
	// lands in subsequent waves.
	GrantRevocations store.GrantRevocationStore

	// RevocationStrategy selects the JWT access-token revocation
	// shape (ADR 0025). The zero value is
	// [store.RevocationStrategyGrantTombstone], which is the
	// documented default; the library wires this from
	// [op.WithAccessTokenRevocationStrategy]. The opaque path
	// (ADR 0024) is unaffected because opaque tokens are
	// intrinsically per-token in storage.
	//
	// Wave 2 plumbs this field; the handler logic that consumes it
	// lands in subsequent waves.
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
		stampNoStore(w)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !isFormContent(r.Header.Get("Content-Type")) {
		writeError(w, http.StatusBadRequest, errInvalidRequest,
			"content-type must be application/x-www-form-urlencoded")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, errInvalidRequest, "malformed form body")
		return
	}
	switch r.PostForm.Get("grant_type") {
	case "":
		writeError(w, http.StatusBadRequest, errInvalidRequest, "grant_type is required")
	case "authorization_code":
		handleAuthorizationCode(w, r, deps)
	case "refresh_token":
		handleRefreshToken(w, r, deps)
	case "client_credentials":
		handleClientCredentials(w, r, deps)
	default:
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
		d.RefreshTokenTTL = defaultRefreshTokenTTL
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
	if deps.RefreshTokenOfflineTTL > 0 && scopeContainsOfflineAccess(scope) {
		return ttlBucketOffline
	}
	return ttlBucketDefault
}

// successResponse is the §5.1 token-endpoint response body shared by
// every successful grant. Optional fields (refresh_token, id_token) are
// omitempty so the wire form matches the spec's "MUST/MAY" guidance.
type successResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope"`
}

// writeSuccess marshals body and writes it with the cache-control and
// content-type headers the token endpoint owes every response.
func writeSuccess(w http.ResponseWriter, body successResponse) {
	stampNoStore(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	// gosec G117 flags the AccessToken field name as "secret-shaped";
	// the field name is required by RFC 6749 §5.1 and the token is the
	// purpose of this response. There is no leak: the value is delivered
	// over TLS to the authenticated client only.
	_ = json.NewEncoder(w).Encode(body) //nolint:gosec // RFC 6749 §5.1 mandates the field name.
}

// authenticate resolves the client credentials carried by the request,
// looks the client up in the registry, and verifies the credentials. The
// boolean second return reports whether the request used HTTP Basic so
// callers can decide whether the 401 path needs a WWW-Authenticate.
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
	creds, err := clientauth.Parse(r)
	usedBasic := r.Header.Get("Authorization") != ""
	if err != nil {
		emitClientAuthnFailure(ctx, deps, "", "", reasonForAuthnError(err))
		writeAuthnError(w, err, usedBasic)
		return nil, nil, false
	}
	if creds.Method == clientauth.MethodPrivateKeyJWT && deps.AssertionVerifier == nil {
		emitClientAuthnFailure(ctx, deps, creds.ClientID, string(creds.Method), "private_key_jwt_disabled")
		writeInvalidClient(w, usedBasic, "private_key_jwt is not enabled")
		return nil, nil, false
	}
	client, err := lookupClient(ctx, deps.Clients, creds.ClientID)
	if err != nil {
		emitClientAuthnFailure(ctx, deps, creds.ClientID, string(creds.Method), reasonForAuthnError(err))
		writeAuthnError(w, err, usedBasic)
		return nil, nil, false
	}
	if _, err := clientauth.VerifyClient(ctx, creds, client, clientauth.VerifyOpts{
		SecretVerifier:    deps.SecretVerifier,
		AssertionVerifier: deps.AssertionVerifier,
		AllowedMethods:    deps.AllowedClientAuthMethods,
	}); err != nil {
		emitClientAuthnFailure(ctx, deps, creds.ClientID, string(creds.Method), reasonForAuthnError(err))
		writeAuthnError(w, err, usedBasic)
		return nil, nil, false
	}
	return client, creds, true
}

// emitClientAuthnFailure raises [audit.Event] for a pre-issuance client
// authentication failure on /token. The event carries the attempted
// client_id (when known), the parsed auth method (when known), and a
// short reason code so SOC tooling can distinguish "wrong secret" from
// "unknown client" probing patterns. The wire response stays at the
// canonical RFC 6749 §5.2 "invalid_client" envelope so the audit stream
// is the only place the failing client_id is surfaced.
func emitClientAuthnFailure(ctx context.Context, deps Deps, clientID, method, reason string) {
	extras := map[string]any{"reason": reason}
	if method != "" {
		extras["method"] = method
	}
	deps.audit().Emit(ctx, audit.Event{
		Name:     auditClientAuthnFailure,
		Level:    audit.LevelWarn,
		Message:  "client authentication failed at token endpoint",
		ClientID: clientID,
		Extras:   extras,
	})
}

// reasonForAuthnError maps a clientauth sentinel onto the short reason
// code emitted on the audit event. The codes match the clientauth error
// names so a reader can grep from an audit line back to the failing
// branch in the verifier.
func reasonForAuthnError(err error) string {
	switch {
	case errors.Is(err, clientauth.ErrNoCredentials):
		return "no_credentials"
	case errors.Is(err, clientauth.ErrAmbiguousCredentials):
		return "ambiguous_credentials"
	case errors.Is(err, clientauth.ErrUnsupportedMethod):
		return "unsupported_method"
	case errors.Is(err, clientauth.ErrClientMismatch):
		return "client_mismatch"
	case errors.Is(err, clientauth.ErrCredentialsInvalid):
		return "invalid_client_credentials"
	case errors.Is(err, clientauth.ErrAssertionMalformed):
		return "assertion_malformed"
	case errors.Is(err, clientauth.ErrAssertionReplayed):
		return "assertion_replayed"
	default:
		return "server_error"
	}
}

// lookupClient resolves the registered client for id, mapping
// [store.ErrNotFound] to [clientauth.ErrCredentialsInvalid] so the caller
// cannot tell "unknown client" apart from "wrong secret" through the
// error surface.
func lookupClient(ctx context.Context, clients store.ClientStore, id string) (*store.Client, error) {
	if id == "" {
		return nil, clientauth.ErrCredentialsInvalid
	}
	c, err := clients.GetClient(ctx, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, clientauth.ErrCredentialsInvalid
		}
		return nil, err
	}
	return c, nil
}

// writeAuthnError maps an authentication error onto the wire response.
// The mapping is the canonical RFC 6749 §5.2 table augmented by this
// library's sentinel discrimination.
func writeAuthnError(w http.ResponseWriter, err error, usedBasic bool) {
	switch {
	case errors.Is(err, clientauth.ErrNoCredentials):
		// No credentials at all: the request reached the token endpoint
		// without any way to authenticate a confidential client and
		// without claiming a public-client identity. Surface 401 with a
		// challenge so RP libraries retry intelligently.
		writeInvalidClient(w, usedBasic, "client authentication required")
	case errors.Is(err, clientauth.ErrAmbiguousCredentials),
		errors.Is(err, clientauth.ErrUnsupportedMethod):
		writeError(w, http.StatusBadRequest, errInvalidRequest,
			"client authentication parameters are malformed")
	case errors.Is(err, clientauth.ErrClientMismatch),
		errors.Is(err, clientauth.ErrCredentialsInvalid),
		errors.Is(err, clientauth.ErrAssertionMalformed),
		errors.Is(err, clientauth.ErrAssertionReplayed):
		writeInvalidClient(w, usedBasic, "client authentication failed")
	default:
		writeError(w, http.StatusInternalServerError, errServerError, "")
	}
}

// isFormContent reports whether ct is application/x-www-form-urlencoded.
// Parameters (charset, etc.) are tolerated so the handler accepts the
// shape RP libraries actually send.
func isFormContent(ct string) bool {
	if ct == "" {
		return false
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.EqualFold(strings.TrimSpace(ct), "application/x-www-form-urlencoded")
}

// scopeContainsOpenID reports whether scopes lists "openid". The check
// is case-sensitive per OIDC Core 1.0 §3.1.2.1: scope tokens are not
// normalised by the server.
func scopeContainsOpenID(scopes []string) bool {
	for _, s := range scopes {
		if s == scopeOpenID {
			return true
		}
	}
	return false
}

// clientPermitsRefresh reports whether the registered client may
// receive refresh tokens. The library issues them only when
// "refresh_token" is in the client's GrantTypes and the granted scope
// carries both "openid" and "offline_access", matching OIDC Core 1.0
// §11 and the project design docs.
func clientPermitsRefresh(c *store.Client, scope []string) bool {
	if !scopeContainsOpenID(scope) {
		return false
	}
	if !scopeContainsOfflineAccess(scope) {
		return false
	}
	for _, g := range c.GrantTypes {
		if g == "refresh_token" {
			return true
		}
	}
	return false
}

// scopeContainsOfflineAccess reports whether scope contains the
// OIDC Core 1.0 §11 "offline_access" token. The match is byte-equal
// per OIDC Core 1.0 §3.1.2.1: scope tokens are case-sensitive and
// the server does not normalise.
func scopeContainsOfflineAccess(scopes []string) bool {
	for _, s := range scopes {
		if s == scopeOfflineAccess {
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
// to defaultRefreshTokenTTL via resolveDeps).
func pickRefreshTokenTTL(deps Deps, scope []string) time.Duration {
	if deps.RefreshTokenOfflineTTL > 0 && scopeContainsOfflineAccess(scope) {
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
