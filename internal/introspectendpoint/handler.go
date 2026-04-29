package introspectendpoint

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
	"github.com/libraz/go-oidc-provider/internal/scoperegistry"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
)

// Defaults the handler applies when [Deps] omits the corresponding field.
const (
	// defaultLeeway is the symmetric tolerance applied to JWT access-token
	// "exp" / "iat" comparisons. The value mirrors the userinfo handler so
	// the two surfaces accept the same set of clock-skewed tokens.
	defaultLeeway = 30 * time.Second

	// maxFormBytes caps the size of an /introspect request body. The
	// endpoint accepts only the form-encoded shape RFC 7662 §2.1
	// describes; a 64 KiB ceiling is far above any legitimate request
	// (the token itself is the largest field, and even a JWT comfortably
	// fits in a few KiB) while bounding memory use against pathological
	// inputs (gosec G120).
	maxFormBytes = 64 * 1024

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
	resp := resolveToken(r.Context(), deps, verifier, client.ID, token, hint)
	if shouldEmitJWT(deps, client, r.Header.Get("Accept")) {
		writeJWTResponse(w, deps, client.ID, resp)
		return
	}
	writeResponse(w, resp)
}

// authenticate resolves the client credentials carried by the request,
// looks the client up in the registry, and verifies the credentials.
// Mirrors the helper in [internal/parendpoint] so the two surfaces share
// an identical authentication contract.
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
// caller cannot tell "unknown client" apart from "wrong secret" through
// the error surface.
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
// library's sentinel discrimination, identical to the token / PAR
// endpoints.
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
// Parameters (charset, boundary, etc.) are tolerated. Mirrors the helper
// in the sibling endpoints so the form-content contract stays uniform.
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
