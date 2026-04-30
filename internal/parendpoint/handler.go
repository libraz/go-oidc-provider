package parendpoint

import (
	"net/http"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/dpop"
	"github.com/libraz/go-oidc-provider/internal/jar"
	"github.com/libraz/go-oidc-provider/internal/scoperegistry"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/store"
)

// Defaults the handler applies when [Deps] omits the corresponding field.
const (
	// DefaultTTL is the lifetime of a persisted PAR record. RFC 9126 §2.2
	// suggests "a short lifetime, typically 60 seconds"; the value here
	// matches the authorization-code TTL so single-use windows stay
	// uniform across the library.
	DefaultTTL = 60 * time.Second

	// maxFormBytes caps the size of a /par request body. The endpoint
	// accepts only the form-encoded shape RFC 9126 §2.1 describes; a
	// 64 KiB ceiling is far above any legitimate request (the largest
	// field, request, comfortably fits in a few KiB) while bounding
	// memory use against pathological inputs (gosec G120).
	maxFormBytes = 64 * 1024

	// uriByteLength is the entropy of the request_uri identifier. RFC 9126
	// §2.2 mandates "sufficient entropy that guessing is infeasible";
	// 32 bytes (256 bits) is the same posture the library uses for
	// authorization codes and refresh tokens.
	uriByteLength = 32

	// uriPrefix is the URN namespace RFC 9126 §2.2 reserves for PAR
	// request_uri values. The full URN is the storage key; consumers at
	// /authorize match on this prefix to distinguish PAR URIs from the
	// (out-of-scope) JAR request_uri.
	uriPrefix = "urn:ietf:params:oauth:request_uri:"
)

// Clock is the package-local view of the wall clock. It mirrors the
// token / authorize endpoint posture: a structurally-typed interface so a
// value satisfying [github.com/libraz/go-oidc-provider/op.Clock] flows
// through without an explicit adapter, and a nil falls back to the system
// clock.
type Clock interface {
	Now() time.Time
}

// Deps bundles the runtime dependencies the PAR endpoint needs. The HTTP
// layer constructs a [Deps] once at startup and passes it to [Handler];
// the handler is otherwise self-contained.
type Deps struct {
	// Issuer is the OP issuer URL. Reserved for future use (audit logs,
	// audience checks); the v1.0 PAR handler does not consult it directly
	// but the field is present so the wire format aligns with the token
	// endpoint and so subsequent FAPI 2.0 work can read it without a
	// breaking change.
	Issuer string

	// Clients is the read-only client registry. The handler looks the
	// authenticated client_id up here before delegating to [authn].
	Clients store.ClientStore

	// PARs is the substore for pushed authorization request records. The
	// handler writes a freshly minted record on every successful POST; the
	// /authorize handler consumes the record exactly once.
	PARs store.PushedAuthRequestStore

	// Scopes is the read-only scope registry the handler consults when
	// validating the requested scope list. A nil value disables only the
	// per-scope AllowedClients allowlist check; the client.Scopes
	// intersection still runs.
	Scopes *scoperegistry.Registry

	// Clock supplies the current wall-clock reading. A nil Clock falls
	// back to [internal/timex.SystemClock].
	Clock Clock

	// SecretVerifier verifies confidential-client secrets. A nil value
	// installs the library default ([clientauth.Argon2id]) so deployments that
	// follow the reference posture need not wire one explicitly.
	SecretVerifier clientauth.SecretVerifier

	// AssertionVerifier verifies private_key_jwt assertions. A nil value
	// disables private_key_jwt support: requests that arrive with a
	// "client_assertion" parameter are rejected as invalid_client. Wire an
	// [clientauth.PrivateKeyJWTVerifier] (or a custom implementation) to support
	// the asymmetric authentication path.
	AssertionVerifier clientauth.AssertionVerifier

	// AllowedClientAuthMethods optionally restricts which client
	// authentication methods the endpoint accepts. See
	// tokenendpoint.Deps.AllowedClientAuthMethods for the full
	// rationale; the rule is applied identically at /par so a request
	// authenticating with client_secret_basic under FAPI 2.0 is
	// rejected at the same wire layer as it would be at /token.
	AllowedClientAuthMethods []clientauth.Method

	// TTL overrides the lifetime of issued request_uri values. Zero or
	// negative falls back to [DefaultTTL].
	TTL time.Duration

	// JAR, when non-nil, makes the PAR endpoint accept a "request"
	// parameter (RFC 9101 §6) inside the request body. The verifier
	// merges the request object's claims onto the wire form before
	// the standard PAR validation path. A nil value rejects "request"
	// with invalid_request_object; "request_uri" inside a /par body
	// is always rejected per RFC 9126 §3.
	JAR *jar.Verifier

	// DPoP, when non-nil, makes /par accept and verify a "DPoP"
	// header (RFC 9449 §4) on the inbound POST. The verifier's
	// thumbprint is bound onto the persisted PAR snapshot as
	// "dpop_jkt" so the eventual /token request must present a
	// proof signed with the same key (RFC 9449 §10.1). The handler
	// also enforces the §10 mismatch rule: when the request
	// already carries a "dpop_jkt" parameter (form or merged
	// request-object claim), it MUST equal the proof's thumbprint.
	// A nil verifier disables both behaviours; the existing form
	// "dpop_jkt" still flows through to the snapshot unchanged.
	DPoP *dpop.Verifier

	// DPoPNonces is the RFC 9449 §8 nonce issuer consulted on the
	// `use_dpop_nonce` challenge response when [Deps.DPoP] rejects a
	// proof for a missing or invalid nonce claim. A nil value omits
	// the "DPoP-Nonce" response header on the challenge but the JSON
	// envelope still carries error="use_dpop_nonce" so a debugger can
	// see the gate triggered. The expected wiring is one struct that
	// satisfies both [dpop.NonceVerifier] (consumed by [Deps.DPoP])
	// and [dpop.NonceIssuer] (this field) so issuance and validation
	// share a rotation pipeline. The token endpoint uses the same
	// pairing — RFC 9449 §8 covers any AS endpoint that processes
	// DPoP proofs, so /par and /token symmetrically issue nonces
	// from the same pool.
	DPoPNonces dpop.NonceIssuer

	// RequireSignedRequestObject, when true, makes /par reject any
	// request that omits the "request" parameter. FAPI 2.0 Message
	// Signing §5.6 mandates "signed_non_repudiation": every
	// authorization request the OP accepts must carry a signed
	// request object. The flag is profile-conditional; Baseline /
	// non-FAPI deployments leave it false so a plain form POST is
	// still acceptable. When set, [Deps.JAR] MUST be non-nil — the
	// constructor in [op] enforces that pairing at startup.
	RequireSignedRequestObject bool

	// RequirePKCE, when true, makes /par reject any request that omits
	// a code_challenge. The flag mirrors
	// [authorizeendpoint.Deps.RequirePKCE]; both endpoints share a
	// validator so a profile that mandates PKCE blocks the same way
	// regardless of whether the client pushes the request first or
	// posts the parameters straight to /authorize.
	RequirePKCE bool

	// RequireNonce, when true, makes /par reject any request that
	// omits the nonce parameter. The flag mirrors
	// [authorizeendpoint.Deps.RequireNonce]; both endpoints share a
	// validator so a profile that mandates nonce blocks the same way
	// at /par and /authorize.
	RequireNonce bool

	// RequireStateOrNonce, when true, makes /par reject any request
	// that carries neither state nor nonce. The flag mirrors
	// [authorizeendpoint.Deps.RequireStateOrNonce]; the FAPI 2.0
	// §5.3.2.1.1 "either a state or a nonce" rule is enforced at
	// both endpoints so a request loses either way.
	RequireStateOrNonce bool

	// OpenIDScopeOptional mirrors
	// [authorizeendpoint.Deps.OpenIDScopeOptional]: when true, /par
	// accepts requests whose scope does not include "openid". The
	// flag is forwarded verbatim to [authorize.Policy.OpenIDScopeOptional]
	// so /par and /authorize stay in lock-step.
	OpenIDScopeOptional bool

	// ClaimsParameterEnabled mirrors
	// [authorizeendpoint.Deps.ClaimsParameterEnabled] for the /par
	// endpoint: when false, any parsed OIDC Core 1.0 §5.5 "claims"
	// payload is discarded before the PAR record is persisted so the
	// downstream /authorize → /token flow behaves as if the
	// parameter had been silently ignored.
	ClaimsParameterEnabled bool
}

// Handler returns the HTTP handler the OP mounts at its PAR endpoint. The
// returned handler is safe for concurrent use; deps MUST NOT be mutated
// after the call.
func Handler(deps Deps) http.Handler {
	resolved := resolveDeps(deps)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serve(w, r, resolved)
	})
}

// resolveDeps fills in defaults the caller chose to omit. The returned
// value is a fresh copy; the caller's [Deps] is not mutated.
func resolveDeps(d Deps) Deps {
	if d.TTL <= 0 {
		d.TTL = DefaultTTL
	}
	if d.SecretVerifier == nil {
		d.SecretVerifier = &clientauth.Argon2id{}
	}
	return d
}

// now returns the wall-clock reading for this request, falling back to the
// system clock when [Deps.Clock] is nil.
func (d *Deps) now() time.Time {
	if d.Clock == nil {
		return timex.SystemClock.Now()
	}
	return d.Clock.Now()
}

// isFormContent reports whether ct is application/x-www-form-urlencoded,
// tolerating optional parameters (charset, boundary, etc.). Mirrors the
// helper in [internal/tokenendpoint] so the two endpoints stay aligned.
func isFormContent(ct string) bool {
	if ct == "" {
		return false
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.EqualFold(strings.TrimSpace(ct), "application/x-www-form-urlencoded")
}
