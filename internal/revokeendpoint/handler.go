package revokeendpoint

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
)

// Defaults the handler applies when [Deps] omits the corresponding
// field.
const (
	// defaultLeeway is the symmetric tolerance applied to JWT
	// access-token "exp" / "iat" comparisons during the
	// acknowledgement check. The value mirrors the introspection
	// handler so the two surfaces accept the same set of
	// clock-skewed tokens.
	defaultLeeway = 30 * time.Second

	// maxFormBytes caps the size of a /revoke request body. The
	// endpoint accepts only the form-encoded shape RFC 7009 §2.1
	// describes; a 64 KiB ceiling is far above any legitimate
	// request (the token itself is the largest field, and even a
	// JWT comfortably fits in a few KiB) while bounding memory use
	// against pathological inputs (gosec G120).
	maxFormBytes = 64 * 1024

	// hintAccessToken / hintRefreshToken are the two values RFC 7009
	// §2.1 defines for "token_type_hint". The handler honours them
	// to skip a lookup but always falls through on miss.
	hintAccessToken  = "access_token"
	hintRefreshToken = "refresh_token"

	// chainWalkLimit caps how far the handler walks parent pointers
	// when computing the chain root for a refresh-token revocation.
	// The value mirrors [internal/grants/refresh.chainWalkLimit] so
	// a corrupted store cannot loop forever; production grants
	// rotate at most once per access-token lifetime, well below the
	// limit.
	chainWalkLimit = 1024
)

// Clock is the package-local view of the wall clock. It mirrors the
// posture of the sibling endpoints: a structurally-typed interface so
// a value satisfying [github.com/libraz/go-oidc-provider/op.Clock]
// flows through without an explicit adapter, and a nil falls back to
// the system clock.
type Clock interface {
	Now() time.Time
}

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
	// [internal/clientauth].
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

	// AccessTokens is the [store.AccessTokenRegistry] consulted by the
	// JWT branch to flip the access-token shadow row to revoked (RFC
	// 7009 §2). The call is idempotent: a missing row returns nil so
	// the endpoint stays on the §2.2 "always 200" path. A nil value
	// disables the per-token revocation surface and the JWT branch
	// falls back to the legacy "no-op acknowledgement" behaviour: the
	// wire response stays 200 but the token continues
	// to verify until exp.
	AccessTokens store.AccessTokenRegistry

	// OpaqueAccessTokens is the [store.OpaqueAccessTokenStore] the
	// opaque-format revocation branch consults (ADR 0024). When the
	// presented bearer is not JWS-shaped the handler hashes it and
	// calls RevokeByID; the call is idempotent so a missing row
	// preserves the RFC 7009 §2.2 "always 200" posture. A nil value
	// disables the opaque branch; non-JWS tokens then silently
	// resolve to 200 without state change, mirroring the JWT-only
	// legacy posture.
	OpaqueAccessTokens store.OpaqueAccessTokenStore

	// GrantRevocations is the [store.GrantRevocationStore] consulted
	// by the grant-tombstone JWT access-token revocation strategy
	// (ADR 0025). The /revoke handler writes a JTI denylist row when
	// an access token is revoked by jti per RFC 7009; cascades that
	// flow through this endpoint write a per-grant tombstone instead.
	// A nil value disables the substore and the handler falls back to
	// whichever legacy behaviour [RevocationStrategy] selects.
	//
	// Wave 2 plumbs this field; the handler logic that consumes it
	// lands in subsequent waves.
	GrantRevocations store.GrantRevocationStore

	// RevocationStrategy selects the JWT access-token revocation
	// shape (ADR 0025). The zero value is
	// [store.RevocationStrategyGrantTombstone], which is the
	// documented default; the library wires this from
	// [op.WithAccessTokenRevocationStrategy].
	//
	// Wave 2 plumbs this field; the handler logic that consumes it
	// lands in subsequent waves.
	RevocationStrategy store.AccessTokenRevocationStrategy
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
	if d.SecretVerifier == nil {
		d.SecretVerifier = &clientauth.Argon2id{}
	}
	return d
}

// newAccessTokenVerifier builds the [tokens.AccessTokenVerifier] the
// JWT branch consults. The verifier is constructed once at startup
// and reused across requests; it holds no per-request state.
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

// serve is the request-scoped entry point. It validates the request
// shape, authenticates the client, dispatches the revocation, and
// writes the response. Decomposing the body keeps the function under
// gocognit's max-complexity gate while remaining readable.
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
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBytes)
	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, errInvalidRequest, "malformed form body")
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
	revokeToken(r.Context(), deps, verifier, client.ID, token, hint)
	writeSuccess(w)
}

// writeSuccess emits the canonical RFC 7009 §2.2 success response: an
// HTTP 200 with an empty body. Cache-Control / Pragma are stamped for
// uniformity with the sibling endpoints; no Content-Type is set
// because there is no media to type.
func writeSuccess(w http.ResponseWriter) {
	stampNoStore(w)
	w.WriteHeader(http.StatusOK)
}

// authenticate resolves the client credentials carried by the
// request, looks the client up in the registry, and verifies the
// credentials. Mirrors the helper in [internal/introspectendpoint] so
// the two surfaces share an identical authentication contract.
//
// The function emits its own response on every failure path so the
// caller only checks the bool: false means "stop, response written".
func authenticate(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	deps Deps,
) (*store.Client, *clientauth.Credentials, bool) {
	creds, err := clientauth.Parse(r)
	usedBasic := r.Header.Get("Authorization") != ""
	if err != nil {
		writeAuthnError(w, err, usedBasic)
		return nil, nil, false
	}
	if creds.Method == clientauth.MethodPrivateKeyJWT && deps.AssertionVerifier == nil {
		writeInvalidClient(w, usedBasic, "private_key_jwt is not enabled")
		return nil, nil, false
	}
	client, err := lookupClient(ctx, deps.Clients, creds.ClientID)
	if err != nil {
		writeAuthnError(w, err, usedBasic)
		return nil, nil, false
	}
	if _, err := clientauth.VerifyClient(ctx, creds, client, clientauth.VerifyOpts{
		SecretVerifier:    deps.SecretVerifier,
		AssertionVerifier: deps.AssertionVerifier,
		AllowedMethods:    deps.AllowedClientAuthMethods,
	}); err != nil {
		writeAuthnError(w, err, usedBasic)
		return nil, nil, false
	}
	return client, creds, true
}

// lookupClient resolves the registered client for id, mapping
// [store.ErrNotFound] to [clientauth.ErrCredentialsInvalid] so the
// caller cannot tell "unknown client" apart from "wrong secret"
// through the error surface.
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

// writeAuthnError maps an authentication error onto the wire
// response. The mapping is the canonical RFC 6749 §5.2 table
// augmented by this library's sentinel discrimination, identical to
// the token / PAR / introspect endpoints.
func writeAuthnError(w http.ResponseWriter, err error, usedBasic bool) {
	switch {
	case errors.Is(err, clientauth.ErrNoCredentials):
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
// Parameters (charset, boundary, etc.) are tolerated. Mirrors the
// helper in the sibling endpoints so the form-content contract stays
// uniform.
func isFormContent(ct string) bool {
	if ct == "" {
		return false
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.EqualFold(strings.TrimSpace(ct), "application/x-www-form-urlencoded")
}

// looksLikeJWT reports whether token has the structural shape of a
// compact-serialised JWS: three base64url segments separated by dots,
// with the header decoding to a JSON object. The check is
// deliberately shallow — full parsing happens inside
// [tokens.AccessTokenVerifier] — because the only purpose of this
// dispatcher is to pick which branch to take.
//
// A token whose header is not valid base64url-encoded JSON is treated
// as opaque so a malformed JWT cannot bypass the opaque lookup; the
// JWT branch would reject it anyway, but the conservative choice
// keeps the dispatcher simple to reason about.
func looksLikeJWT(token string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false
	}
	if parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return false
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return false
	}
	return len(header) > 0
}
