package introspectendpoint

import (
	"context"
	"net/http"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/clientencjwks"
	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/internal/httpx"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/scoperegistry"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
)

// introspectSingleValuedParams is the closed list of RFC 7662 §2.1
// request parameters and shared client-authentication credentials that
// must not appear more than once.
//
//nolint:gochecknoglobals // closed allow-list, intentional package state.
var introspectSingleValuedParams = []string{
	"token",
	"token_type_hint",
	"client_id",
	"client_secret",
	"client_assertion_type",
	"client_assertion",
}

// Audit event names mirrored from the public op.AuditEvent catalogue.
// internal/introspectendpoint cannot import op/, so the strings are
// duplicated and TestAuditEvent_IntrospectionMirror in op/audit_test.go
// pins the values together.
const (
	auditIntrospectionError = "introspection.error"
)

// Defaults the handler applies when [Deps] omits the corresponding field.
const (
	// defaultLeeway is the symmetric tolerance applied to JWT access-token
	// "exp" / "iat" comparisons. The value mirrors the userinfo handler so
	// the two surfaces accept the same set of clock-skewed tokens.
	defaultLeeway = 30 * time.Second

	// tokenTypeBearer is the value the "token_type" introspection claim
	// carries for both opaque and JWT bearer tokens (RFC 7662 §2.2).
	// RFC 9449 §6 does not rename the type for DPoP-bound tokens — the
	// binding surfaces through "cnf.jkt" — so v1.0 always emits
	// "Bearer".
	tokenTypeBearer = "Bearer"

	// hintAccessToken / hintRefreshToken are the two values RFC 7662
	// §2.1 defines for "token_type_hint". The handler honours them to
	// skip a lookup but always falls through on miss.
	hintAccessToken  = "access_token"
	hintRefreshToken = "refresh_token"
)

// Clock is the package-local view of the wall clock. It mirrors the
// posture of the sibling endpoints: a structurally-typed interface so a
// value satisfying [github.com/libraz/go-oidc-provider/op.Clock] flows
// through without an explicit adapter, and a nil falls back to the
// system clock.
type Clock interface {
	Now() time.Time
}

// Deps bundles the runtime dependencies the introspection endpoint
// needs. The HTTP layer constructs a [Deps] once at startup and passes
// it to [Handler]; the handler is otherwise self-contained.
type Deps struct {
	// Issuer is the OP issuer URL. The JWT branch compares it against
	// the access token's "iss" claim; an empty value disables the check
	// and SHOULD only be used in tests.
	Issuer string

	// Clients is the read-only client registry. The handler looks the
	// authenticated client_id up here before delegating to
	// [internal/clientauth].
	Clients store.ClientStore

	// RefreshTokens is the substore for refresh tokens. A nil value
	// disables the opaque path: opaque tokens always project onto
	// inactive. JWT introspection still functions because it does not
	// consult the refresh-token store.
	RefreshTokens store.RefreshTokenStore

	// Grants is the consent substore. The opaque-access-token and
	// refresh-token branches read it by GrantID to echo the RFC 9396
	// authorization_details the grant was issued with. A nil value
	// simply omits authorization_details from the response.
	Grants store.GrantStore

	// Keys is the active OP keyset. Required so the JWT branch can
	// verify access-token signatures; the active key plus all retiring
	// keys MUST be present so tokens minted before a rotation continue
	// to verify.
	Keys *keys.Set

	// Scopes is the read-only scope registry. Reserved for future use
	// (per-scope introspection ACLs); v1.0 does not consult it but the
	// field is present so the wire shape aligns with the sibling
	// endpoints and a later release can read it without a breaking
	// change.
	Scopes *scoperegistry.Registry

	// Clock supplies the current wall-clock reading. A nil Clock falls
	// back to [internal/timex.SystemClock].
	Clock Clock

	// SecretVerifier verifies confidential-client secrets. A nil value
	// installs the library default ([clientauth.Argon2id]) so
	// deployments that follow the reference posture need not wire one
	// explicitly.
	SecretVerifier clientauth.SecretVerifier

	// AssertionVerifier verifies private_key_jwt assertions. A nil
	// value disables private_key_jwt support: requests that arrive
	// with a "client_assertion" parameter are rejected as
	// invalid_client.
	AssertionVerifier clientauth.AssertionVerifier

	// AllowedClientAuthMethods optionally restricts which client
	// authentication methods the endpoint accepts. See
	// tokenendpoint.Deps.AllowedClientAuthMethods for the rationale;
	// the rule is applied identically at /introspect.
	AllowedClientAuthMethods []clientauth.Method

	// Leeway overrides the symmetric tolerance the JWT verifier
	// applies to "exp" / "iat" comparisons. Zero or negative falls
	// back to [defaultLeeway].
	Leeway time.Duration

	// SigningKey is the OP active key used to sign JWT-formatted
	// introspection responses (RFC 9701). A zero value disables JWT
	// introspection: the handler ignores Accept negotiation and always
	// emits JSON. The op layer wires this from the active keyset entry,
	// so production deployments always have a non-zero value.
	SigningKey tokens.SigningKey

	// RequireSignedIntrospection forces every successful introspection
	// response onto the RFC 9701 JWT envelope, regardless of client
	// metadata or Accept negotiation. FAPI 2.0 Message Signing §5
	// mandates this posture: an Accept header asking for JSON does not
	// override a profile that requires signed responses. The op layer
	// wires this from the active profile set; the build-time profile
	// validator already requires a working keyset, so true here means
	// SigningKey.Signer is guaranteed to be non-nil.
	RequireSignedIntrospection bool

	// AccessTokens is the [store.AccessTokenRegistry] the JWT branch
	// consults after signature / issuer validation passes. A revoked
	// or absent record collapses the response onto {"active": false}
	// per RFC 7662 §2.2 — no error_description, no leakage of
	// issuance metadata. A nil value disables the check entirely; the
	// handler then reports {"active": true} for any token that
	// verifies and is still inside its exp window, mirroring the
	// legacy behaviour.
	AccessTokens store.AccessTokenRegistry

	// OpaqueAccessTokens is the [store.OpaqueAccessTokenStore] the
	// opaque-format introspection branch consults (ADR 0024). When
	// the presented bearer is not JWS-shaped the handler hashes it,
	// looks the digest up here, and projects the resulting record
	// onto the RFC 7662 §2.2 wire shape (revoked / expired /
	// cross-client → {"active": false}). A nil value disables the
	// opaque branch; opaque tokens then always project onto
	// inactive, mirroring the JWT-only legacy posture.
	OpaqueAccessTokens store.OpaqueAccessTokenStore

	// GrantRevocations is the [store.GrantRevocationStore] consulted
	// by the grant-tombstone JWT access-token revocation strategy
	// (ADR 0025). The introspection handler uses it to collapse a
	// tombstoned access token onto the RFC 7662 §2.2
	// {"active": false} wire shape; the lookup is keyed by the AT's
	// "gid" private claim. A nil value disables the lookup and the
	// handler falls back to whichever legacy behaviour
	// [RevocationStrategy] selects.
	GrantRevocations store.GrantRevocationStore

	// RevocationStrategy selects the JWT access-token revocation
	// shape (ADR 0025). The zero value is
	// [store.RevocationStrategyGrantTombstone], which is the
	// documented default; the library wires this from
	// [op.WithAccessTokenRevocationStrategy].
	RevocationStrategy store.AccessTokenRevocationStrategy

	// Audit is the structured audit-event sink. A nil Emitter falls
	// back to [audit.Discard] so the handler can call the emitter
	// unconditionally. The introspection endpoint emits
	// "introspection.error" on every pre-authentication failure
	// (invalid_client / malformed credentials / private_key_jwt
	// disabled). The wire response stays at the RFC 6749 §5.2
	// canonical shape; the audit event surfaces the attempted
	// client_id and a short reason code for SOC tooling.
	Audit audit.Emitter

	// ClientEncJWKs resolves the RP's encryption recipient when the
	// client registered introspection_encrypted_response_alg / _enc
	// (RFC 7662 + draft JWT Response for OAuth Token Introspection;
	// RFC 9701 §5). The handler wraps a signed JWT introspection
	// response in a JWE addressed to the RP's `use=enc` key. A nil
	// value disables outbound introspection encryption.
	ClientEncJWKs *clientencjwks.Resolver

	// SubjectProjector, when non-nil, converts the OP-internal raw
	// subject from an opaque-AT or refresh-token store record into the
	// per-client pairwise value the introspection response surfaces.
	// JWT access tokens already carry the projected value in "sub"
	// (the token endpoint stamps it at mint time so RS-visible "sub"
	// matches id_token "sub" per RFC 9068 §3) and bypass this hook.
	// A nil value leaves the raw subject on the wire, which is the
	// correct posture when the OP is not configured for pairwise.
	SubjectProjector func(ctx context.Context, raw string, client *store.Client) (string, error)
}

// Handler returns the HTTP handler the OP mounts at its introspection
// endpoint. The returned handler is safe for concurrent use; deps MUST
// NOT be mutated after the call.
func Handler(deps Deps) http.Handler {
	resolved := resolveDeps(deps)
	verifier := newAccessTokenVerifier(resolved)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serve(w, r, resolved, verifier)
	})
}

// resolveDeps fills in defaults the caller chose to omit. The returned
// value is a fresh copy; the caller's [Deps] is not mutated.
func resolveDeps(d Deps) Deps {
	if d.Leeway <= 0 {
		d.Leeway = defaultLeeway
	}
	if d.SecretVerifier == nil {
		d.SecretVerifier = &clientauth.Argon2id{}
	}
	return d
}

// newAccessTokenVerifier builds the [tokens.AccessTokenVerifier] the JWT
// branch consults. The verifier is constructed once at startup and
// reused across requests; it holds no per-request state.
func newAccessTokenVerifier(d Deps) *tokens.AccessTokenVerifier {
	var verifierClock tokens.Clock
	if d.Clock != nil {
		verifierClock = d.Clock
	}
	return &tokens.AccessTokenVerifier{
		Keys:   d.Keys,
		Issuer: d.Issuer,
		Clock:  verifierClock,
		Leeway: d.Leeway,
	}
}

// now returns the wall-clock reading for this request, falling back to
// the system clock when [Deps.Clock] is nil.
func (d *Deps) now() time.Time {
	if d.Clock == nil {
		return timex.SystemClock.Now()
	}
	return d.Clock.Now()
}

// serve is the request-scoped entry point. It validates the request
// shape, authenticates the client, resolves the token, and writes the
// response. Decomposing the body keeps the function under cyclop's
// max-complexity gate while remaining readable.
func serve(w http.ResponseWriter, r *http.Request, deps Deps, verifier *tokens.AccessTokenVerifier) {
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
	endpointsupport.LimitFormBody(w, r)
	if err := r.ParseForm(); err != nil { //nolint:gosec // body bounded by LimitFormBody above
		writeError(w, http.StatusBadRequest, errInvalidRequest, "malformed form body")
		return
	}
	if name, ok := httpx.FirstDuplicateParameter(r.PostForm, introspectSingleValuedParams); !ok {
		writeError(w, http.StatusBadRequest, errInvalidRequest,
			"parameter "+name+" must not be repeated")
		return
	}
	client, _, ok := authenticate(r.Context(), w, r, deps)
	if !ok {
		return
	}
	token := r.PostForm.Get("token")
	if token == "" {
		writeError(w, http.StatusBadRequest, errInvalidRequest, "token is required")
		return
	}
	hint := r.PostForm.Get("token_type_hint")
	resp := resolveToken(r.Context(), deps, verifier, client.ID, token, hint)
	if shouldEmitJWT(deps, client, r.Header.Get("Accept")) {
		writeJWTResponse(r.Context(), w, deps, client, client.ID, resp)
		return
	}
	writeResponse(w, resp)
}

// authenticate resolves the client credentials carried by the request,
// looks the client up in the registry, and verifies the credentials.
// Delegates to [endpointsupport.AuthenticateClient] so the wire
// contract stays identical to the token / par / revoke endpoints.
//
// The function emits its own response on every failure path so the
// caller only checks the bool: false means "stop, response written".
// Each failure path also raises an "introspection.error" audit event so
// SOC tooling can spot probing for a known client_id even though the
// wire response stays at the RFC 6749 §5.2 canonical shape.
func authenticate(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	deps Deps,
) (*store.Client, *clientauth.Credentials, bool) {
	return endpointsupport.AuthenticateClient(ctx, w, r,
		endpointsupport.AuthenticateOpts{
			Clients:           deps.Clients,
			SecretVerifier:    deps.SecretVerifier,
			AssertionVerifier: deps.AssertionVerifier,
			AllowedMethods:    deps.AllowedClientAuthMethods,
		},
		func(creds *clientauth.Credentials, err error) {
			clientID := ""
			if creds != nil {
				clientID = creds.ClientID
			}
			endpointsupport.EmitAuthnFailure(ctx, deps.auditEmitter(),
				auditIntrospectionError,
				"introspection client authentication failed",
				clientID, err)
		},
	)
}

// auditEmitter returns the configured audit sink, or a [audit.Discard]
// emitter so call sites can invoke Emit unconditionally.
func (d *Deps) auditEmitter() audit.Emitter {
	if d.Audit == nil {
		return audit.Discard()
	}
	return d.Audit
}

// isFormContent reports whether ct is application/x-www-form-urlencoded.
// Parameters (charset, boundary, etc.) are tolerated. Delegates to
// [endpointsupport.IsFormContent] so the form-content contract stays
// uniform across endpoints.
func isFormContent(ct string) bool {
	return endpointsupport.IsFormContent(ct)
}

// looksLikeJWT reports whether token has the structural shape of a
// compact-serialised JWS: three base64url segments separated by dots,
// with the header decoding to a JSON object. The check is deliberately
// shallow — full parsing happens inside [tokens.AccessTokenVerifier] —
// because the only purpose of this dispatcher is to pick which branch
// to take.
//
// A token whose header is not valid base64url-encoded JSON is treated
// as opaque so a malformed JWT cannot bypass the opaque lookup; the
// JWT branch would reject it anyway, but the conservative choice keeps
// the dispatcher simple to reason about.
func looksLikeJWT(token string) bool {
	return endpointsupport.LooksLikeJWT(token)
}
