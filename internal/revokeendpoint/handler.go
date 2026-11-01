package revokeendpoint

import (
	"context"
	"net/http"
	"time"

	"github.com/libraz/go-oidc-provider/internal/timex"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/internal/httpx"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
)

// Defaults the handler applies when [Deps] omits the corresponding
// field.
const (
	// defaultLeeway is the symmetric tolerance applied to JWT
	// access-token "exp" / "iat" comparisons during the
	// acknowledgement check. It is an alias for [tokens.DefaultLeeway]
	// rather than a copy of its value: every surface that verifies an
	// access token has to accept the same set of clock-skewed tokens,
	// and a restated literal agrees only until someone edits one of
	// them.
	defaultLeeway = tokens.DefaultLeeway
)

// Clock is the package-local name for the shared wall-clock interface; a nil
// Clock falls back to the system clock.
type Clock = timex.Clock

// Deps bundles the runtime dependencies the revocation endpoint needs.
// The HTTP layer constructs a [Deps] once at startup and passes it to
// [Handler]; the handler is otherwise self-contained.
type Deps struct {
	// Issuer is the OP issuer URL. The JWT branch compares it
	// against the access token's "iss" claim; an empty value
	// disables the check and SHOULD only be used in tests.
	Issuer string

	// Clients is the read-only client registry. The handler looks
	// the authenticated client_id up here before delegating to
	// internal/clientauth.
	Clients store.ClientStore

	// RefreshTokens is the substore for refresh tokens. A nil value
	// disables the opaque path: opaque tokens always silently 200.
	// JWT acknowledgement still functions because it does not
	// consult the refresh-token store.
	RefreshTokens store.RefreshTokenStore

	// Keys is the active OP keyset. Required so the JWT branch can
	// verify access-token signatures during the acknowledgement
	// check.
	Keys *keys.Set

	// Clock supplies the current wall-clock reading the JWT
	// access-token verifier consults for "exp" / "iat" comparisons.
	// A nil Clock leaves the verifier's own default (system clock)
	// in place. The opaque branch does not perform expiry
	// comparisons at the HTTP layer — an expired record is treated
	// as already-gone and the response stays 200 either way — so
	// this field only affects the JWT acknowledgement path.
	Clock Clock

	// SecretVerifier verifies confidential-client secrets. A nil
	// value installs the library default ([clientauth.Argon2id]) so
	// deployments that follow the reference posture need not wire
	// one explicitly.
	SecretVerifier clientauth.SecretVerifier

	// AssertionVerifier verifies private_key_jwt assertions. A nil
	// value disables private_key_jwt support: requests that arrive
	// with a "client_assertion" parameter are rejected as
	// invalid_client.
	AssertionVerifier clientauth.AssertionVerifier

	// AllowedClientAuthMethods optionally restricts which client
	// authentication methods the endpoint accepts. See
	// tokenendpoint.Deps.AllowedClientAuthMethods for the rationale;
	// the rule is applied identically at /revoke.
	AllowedClientAuthMethods []clientauth.Method

	// Leeway overrides the symmetric tolerance the JWT verifier
	// applies to "exp" / "iat" comparisons. Zero or negative falls
	// back to [defaultLeeway].
	Leeway time.Duration

	// AccessTokens is the [store.AccessTokenRegistry] the JWT branch
	// flips to revoked (RFC 7009 §2) under
	// [store.RevocationStrategyJTIRegistry], and under the grant-tombstone
	// strategy when [Deps.GrantRevocations] is nil. The call is
	// idempotent: a missing row returns nil so the endpoint stays on the
	// §2.2 "always 200" path. When neither substore backs the active
	// strategy the JWT branch persists nothing: the wire response stays
	// 200, no token.revoked event is recorded, and the token verifies
	// until exp.
	AccessTokens store.AccessTokenRegistry

	// OpaqueAccessTokens is the [store.OpaqueAccessTokenStore] the
	// opaque-format revocation branch consults. When the presented
	// bearer is not JWS-shaped the handler hashes it and calls
	// RevokeByID; the call is idempotent so a missing row preserves the
	// RFC 7009 §2.2 "always 200" posture. A nil value disables the
	// opaque branch; non-JWS tokens then silently resolve to 200 without
	// state change, mirroring the JWT-only legacy posture.
	OpaqueAccessTokens store.OpaqueAccessTokenStore

	// GrantRevocations is the [store.GrantRevocationStore] consulted by
	// the grant-tombstone JWT access-token revocation strategy. The
	// /revoke handler writes a JTI denylist row when an access token is
	// revoked by jti per RFC 7009; cascades that flow through this
	// endpoint write a per-grant tombstone instead. A nil value disables
	// the substore and the handler falls back to whichever legacy
	// behaviour [RevocationStrategy] selects.
	GrantRevocations store.GrantRevocationStore

	// RevocationStrategy selects the JWT access-token revocation shape.
	// The zero value is [store.RevocationStrategyGrantTombstone], which
	// is the documented default; the library wires this from
	// [op.WithAccessTokenRevocationStrategy].
	RevocationStrategy store.AccessTokenRevocationStrategy

	// AccessTokenTTL is the issued access-token lifetime. It sizes the
	// grant-tombstone retention window (AT TTL + clock-skew grace) when a
	// refresh-token revocation cascades to the grant's access tokens
	// (RFC 7009 §2.1). A zero value falls back to a one-hour ceiling,
	// mirroring the /end_session cascade.
	AccessTokenTTL time.Duration

	// Audit is the structured audit-event sink. A nil Emitter falls
	// back to [audit.Discard] so the handler can call the emitter
	// unconditionally. The /revoke endpoint emits "token.revoke_failed"
	// when a non-NotFound storage fault prevents a record from being
	// flipped to revoked. The wire response stays HTTP 200 per RFC
	// 7009 §2.2 ("invalid tokens do not cause an error response"); the
	// audit event lets SOC tooling detect the silent-failure class
	// (GHSA-7mqr-2v3q-v2wm) without violating the spec response
	// contract.
	Audit audit.Emitter
}

// audit returns the configured audit sink, or a [audit.Discard]
// emitter so call sites can invoke Emit unconditionally.
func (d *Deps) audit() audit.Emitter {
	return audit.OrDiscard(d.Audit)
}

// Handler returns the HTTP handler the OP mounts at its revocation
// endpoint. The returned handler is safe for concurrent use; deps
// MUST NOT be mutated after the call.
func Handler(deps Deps) http.Handler {
	resolved := resolveDeps(deps)
	verifier := newAccessTokenVerifier(resolved)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serve(w, r, resolved, verifier)
	})
}

// resolveDeps fills in defaults the caller chose to omit. The
// returned value is a fresh copy; the caller's [Deps] is not mutated.
func resolveDeps(d Deps) Deps {
	if d.Leeway <= 0 {
		d.Leeway = defaultLeeway
	}
	return d
}

// newAccessTokenVerifier builds the [tokens.AccessTokenVerifier] the
// JWT branch consults. The verifier is constructed once at startup
// and reused across requests; it holds no per-request state.
func newAccessTokenVerifier(d Deps) *tokens.AccessTokenVerifier {
	return endpointsupport.NewAccessTokenVerifier(d.Keys, d.Issuer, d.Clock, d.Leeway, d.RevocationStrategy)
}

// serve is the request-scoped entry point. It validates the request
// shape, authenticates the client, dispatches the revocation, and
// writes the response. Decomposing the body keeps the function under
// gocognit's max-complexity gate while remaining readable.
func serve(w http.ResponseWriter, r *http.Request, deps Deps, verifier *tokens.AccessTokenVerifier) {
	if !endpointsupport.ParseFormRequest(w, r, endpointsupport.TokenLookupSingleValuedParams) {
		return
	}
	client, _, ok := authenticate(r.Context(), w, r, deps)
	if !ok {
		return
	}
	token := r.PostForm.Get("token")
	if token == "" {
		endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errInvalidRequest, "token is required")
		return
	}
	hint := r.PostForm.Get("token_type_hint")
	revokeToken(r.Context(), deps, verifier, client.ID, token, hint)
	writeSuccess(w)
}

// writeSuccess emits the canonical RFC 7009 §2.2 success response: an
// HTTP 200 with an empty body. Cache-Control / Pragma are stamped for
// uniformity with the sibling endpoints; no Content-Type is set
// because there is no media to type.
func writeSuccess(w http.ResponseWriter) {
	httpx.StampNoStore(w)
	w.WriteHeader(http.StatusOK)
}

// authenticate resolves the client credentials carried by the
// request, looks the client up in the registry, and verifies the
// credentials. Delegates to [endpointsupport.AuthenticateClient] so
// the wire contract stays identical to the introspect / par / token
// endpoints.
//
// The function emits its own response on every failure path so the
// caller only checks the bool: false means "stop, response written".
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
			Now:               timex.OrSystem(deps.Clock).Now().UTC(),
			Audit:             deps.audit(),
		},
		// /revoke does not raise an audit event on pre-authentication
		// failures: RFC 7009 §2.2 collapses the success path to "always
		// 200 with empty body", and an audit hook would surface
		// probing patterns the spec deliberately hides. The
		// failure-mode hook stays nil so the helper falls through
		// without emitting anything.
		nil,
	)
}
