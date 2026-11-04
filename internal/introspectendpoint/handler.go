package introspectendpoint

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/auditevent"
	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/clientencjwks"
	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/scoperegistry"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
)

// Audit event names sourced from the typed registry that backs the public
// op/audit.Event catalog.
const (
	auditIntrospectionError = string(auditevent.AuditIntrospectionError)
)

// Defaults the handler applies when [Deps] omits the corresponding field.
const (
	// tokenTypeBearer is the value the "token_type" introspection claim
	// carries for both opaque and JWT bearer tokens (RFC 7662 §2.2).
	// RFC 9449 §6 does not rename the type for DPoP-bound tokens — the
	// binding surfaces through "cnf.jkt" — so v1.0 always emits
	// "Bearer".
	tokenTypeBearer = "Bearer"
)

// Clock is the package-local name for the shared wall-clock interface; a nil
// Clock falls back to the system clock.
type Clock = timex.Clock

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
	// internal/clientauth.
	Clients store.ClientStore

	// IntrospectionDelegates maps a client_id to the set of
	// canonicalised resource identifiers that client may introspect
	// access tokens for, even when the token was issued to somebody
	// else. It is derived from the resource-server metadata the
	// embedder registered.
	//
	// A nil or empty map keeps the endpoint same-client-only, which is
	// the default posture. The map is read-only after construction.
	// Refresh tokens are never resolved through it: a refresh token is
	// the client's own credential, not something a resource server is
	// ever presented with, so relaxing its owner check would hand a
	// resource server a credential it has no use for.
	IntrospectionDelegates map[string]map[string]struct{}

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
	// back to [timex.SystemClock].
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

	// CertificateVerifier verifies RFC 8705 §2 mTLS client
	// authentication (tls_client_auth, self_signed_tls_client_auth). Nil
	// when feature.MTLS is off, which rejects a client registered for
	// either method as invalid_client.
	CertificateVerifier clientauth.CertificateVerifier

	// AllowedClientAuthMethods optionally restricts which client
	// authentication methods the endpoint accepts. See
	// tokenendpoint.Deps.AllowedClientAuthMethods for the rationale;
	// the rule is applied identically at /introspect.
	AllowedClientAuthMethods []clientauth.Method

	// Leeway overrides the symmetric tolerance the JWT verifier
	// applies to "exp" / "iat" comparisons. Zero or negative falls
	// back to [tokens.DefaultLeeway].
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
	// opaque-format introspection branch consults. When the presented
	// bearer is not JWS-shaped the handler hashes it, looks the digest
	// up here, and projects the resulting record onto the RFC 7662 §2.2
	// wire shape (revoked / expired / cross-client → {"active": false}).
	// A nil value disables the opaque branch; opaque tokens then always
	// project onto inactive, mirroring the JWT-only legacy posture.
	OpaqueAccessTokens store.OpaqueAccessTokenStore

	// GrantRevocations is the [store.GrantRevocationStore] consulted by
	// the grant-tombstone JWT access-token revocation strategy. The
	// introspection handler uses it to collapse a tombstoned access
	// token onto the RFC 7662 §2.2 {"active": false} wire shape; the
	// lookup is keyed by the AT's "gid" private claim. A nil value
	// disables the lookup and the handler falls back to whichever legacy
	// behaviour [RevocationStrategy] selects.
	GrantRevocations store.GrantRevocationStore

	// RevocationStrategy selects the JWT access-token revocation shape.
	// The zero value is [store.RevocationStrategyGrantTombstone], which
	// is the documented default; the library wires this from
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
	verifier := newAccessTokenVerifier(deps)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serve(w, r, deps, verifier)
	})
}

// newAccessTokenVerifier builds the [tokens.AccessTokenVerifier] the JWT
// branch consults. The verifier is constructed once at startup and
// reused across requests; it holds no per-request state.
func newAccessTokenVerifier(d Deps) *tokens.AccessTokenVerifier {
	return endpointsupport.NewAccessTokenVerifier(d.Keys, d.Issuer, d.Clock, d.Leeway, d.RevocationStrategy)
}

// now returns the wall-clock reading for this request, falling back to
// the system clock when [Deps.Clock] is nil.
func (d *Deps) now() time.Time {
	return timex.OrSystem(d.Clock).Now()
}

// serve is the request-scoped entry point. It validates the request
// shape, authenticates the client, resolves the token, and writes the
// response. Decomposing the body keeps the function under cyclop's
// max-complexity gate while remaining readable.
func serve(w http.ResponseWriter, r *http.Request, deps Deps, verifier *tokens.AccessTokenVerifier) {
	if !endpointsupport.ParseFormRequest(w, r, endpointsupport.TokenLookupSingleValuedParams) {
		return
	}
	client, _, ok := authenticate(r.Context(), w, r, deps)
	if !ok {
		return
	}
	if !isConfidentialIntrospectionClient(client) {
		err := errors.New("introspection requires a confidential client")
		clientID := ""
		if client != nil {
			clientID = client.ID
		}
		endpointsupport.EmitAuthnFailure(r.Context(), deps.auditEmitter(), auditIntrospectionError,
			"introspection client authentication rejected", clientID, err)
		endpointsupport.WriteOAuthError(w, http.StatusUnauthorized, endpointsupport.ErrInvalidClient, err.Error())
		return
	}
	token := r.PostForm.Get("token")
	if token == "" {
		endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errInvalidRequest, "token is required")
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

func isConfidentialIntrospectionClient(client *store.Client) bool {
	return client != nil && !clientauth.IsPublicClient(client)
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
			Clients:             deps.Clients,
			SecretVerifier:      deps.SecretVerifier,
			AssertionVerifier:   deps.AssertionVerifier,
			CertificateVerifier: deps.CertificateVerifier,
			AllowedMethods:      deps.AllowedClientAuthMethods,
			Now:                 deps.now(),
			Audit:               deps.auditEmitter(),
		},
		endpointsupport.AuditAuthnFailure(ctx, deps.auditEmitter(), auditIntrospectionError,
			"introspection client authentication failed"),
	)
}

// auditEmitter returns the configured audit sink, or a [audit.Discard]
// emitter so call sites can invoke Emit unconditionally.
func (d *Deps) auditEmitter() audit.Emitter {
	return audit.OrDiscard(d.Audit)
}
