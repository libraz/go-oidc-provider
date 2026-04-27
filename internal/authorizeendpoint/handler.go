package authorizeendpoint

import (
	"net/http"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/csrf"
	"github.com/libraz/go-oidc-provider/internal/jar"
	"github.com/libraz/go-oidc-provider/internal/jarm"
	"github.com/libraz/go-oidc-provider/internal/scoperegistry"
	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
)

// Default timing budgets the handler uses when [Deps] does not override
// them. The values match docs/plans/002-product-design.md §F.1 (interaction
// cookie lifetime) and §A.12 (authorization-code TTL).
const (
	// DefaultAuthCodeTTL is the lifetime of an issued authorization code.
	// 60 seconds is well below the RFC 6749 §4.1.2 ceiling and matches
	// the FAPI 2.0 baseline.
	DefaultAuthCodeTTL = 60 * time.Second

	// DefaultInteractionTTL is the lifetime of an interaction record.
	// One hour matches the [internal/cookie.InteractionProfile] MaxAge so
	// the cookie and the store row expire together.
	DefaultInteractionTTL = time.Hour

	// uidByteLength is the entropy of generated interaction UIDs. 16
	// bytes (128 bits) is well above the birthday bound for the lifetime
	// of a single OP deployment.
	uidByteLength = 16

	// codeByteLength is the entropy of authorization-code identifiers.
	// 32 bytes (256 bits) matches the FAPI 2.0 advisory ceiling and the
	// existing posture of session / refresh identifiers.
	codeByteLength = 32

	// interactionAAD is the AEAD additional data used when sealing the
	// interaction UID into the __Host-oidc_interaction cookie. Pinning
	// the AAD prevents cookie payloads from authenticating against
	// __Host-oidc_session (which uses "oidc-session").
	interactionAAD = "oidc-interaction"
)

// Clock is the structural wall-clock dependency, mirroring the interface in
// [internal/tokenendpoint] so a value satisfying [op.Clock] flows through
// without an adapter. A nil [Deps.Clock] falls back to the system clock.
type Clock interface {
	Now() time.Time
}

// Deps bundles the runtime dependencies the handler needs. The HTTP layer
// constructs a [Deps] once at startup and passes it to [Handler]; the
// handler is otherwise self-contained.
type Deps struct {
	// Clients is the read-only client registry. Used to confirm the
	// request's client_id and redirect_uri before any state mutation.
	Clients store.ClientStore

	// Codes is the substore for authorization codes. The handler writes
	// freshly minted codes here for the token endpoint to consume.
	Codes store.AuthorizationCodeStore

	// Grants is the consent substore. The handler reads (subject, client)
	// to decide whether a re-consent prompt is required and writes a
	// fresh grant when consent succeeds.
	Grants store.GrantStore

	// Interactions is the substore for in-progress UI interactions. The
	// handler writes a record on /authorize → /interaction redirects and
	// deletes it on terminal outcomes (cancel, success, abort).
	Interactions store.InteractionStore

	// PARs is the substore for pushed authorization request records. A
	// nil value disables PAR consumption: requests carrying a request_uri
	// are rejected as invalid_request. The library wires this only when
	// the [feature.PAR] flag is enabled; embedders that build the handler
	// directly may leave the field nil to opt out.
	PARs store.PushedAuthRequestStore

	// JARM is the signer the handler uses when the request opts into a
	// JARM response_mode. A nil value means "feature off": JARM modes
	// are rejected with the OAuth wire code "unsupported_response_mode"
	// and emitted as a plain redirect (success / error). The library
	// wires this only when the [feature.JARM] flag is enabled.
	JARM *jarm.Signer

	// JAR is the verifier for RFC 9101 signed authorization requests.
	// A nil value means "feature off": "request" / "request_uri"
	// parameters at /authorize are rejected with invalid_request and
	// the corresponding metadata is suppressed in discovery. The
	// library wires this only when the [feature.JAR] flag is enabled.
	JAR *jar.Verifier

	// Sessions is the chooser-group session manager. The handler reads
	// the active session via [sessions.Manager.Resolve] before deciding
	// whether interaction is required, and calls [sessions.Manager.Issue]
	// after a fresh login terminates the interaction.
	Sessions *sessions.Manager

	// CookieCodec is the underlying AES-256-GCM codec used to seal the
	// __Host-oidc_interaction cookie value (the interaction UID).
	CookieCodec *cookie.Codec

	// CSRF is the HMAC signer for double-submit tokens.
	CSRF *csrf.Signer

	// Origins is the Origin / Referer allowlist enforced on every state-
	// changing /interaction request.
	Origins *csrf.Allowlist

	// Driver is the [interaction.Driver] the handler delegates UI
	// rendering to. A nil value falls back to [interaction.JSONDriver].
	Driver interaction.Driver

	// Authn is the orchestrator that drives the chain of
	// [op.Authenticator] / [op.Interaction] across /interaction
	// requests. The HTTP layer feeds it [authn.Input] on every Tick
	// and persists the returned [authn.State] back into the
	// interaction record. Required.
	Authn *authn.Orchestrator

	// Scopes is the read-only scope registry the handler consults
	// when validating the requested scope list. A nil value disables
	// only the per-scope AllowedClients allowlist check; the
	// client.Scopes intersection still runs.
	Scopes *scoperegistry.Registry

	// AuthorizePath is the mount-prefix-aware path of the /authorize
	// endpoint. The handler dispatches its own internal mux against this
	// value so the same handler instance can serve both /authorize and
	// /interaction without the caller wiring two separate http.Handlers.
	AuthorizePath string

	// InteractionPath is the mount-prefix-aware path of the /interaction
	// prefix; the handler appends "/{uid}". The value MUST NOT carry a
	// trailing slash.
	InteractionPath string

	// Clock supplies the current wall-clock reading. A nil value falls
	// back to [internal/timex.SystemClock].
	Clock Clock

	// AuthCodeTTL is the lifetime of issued authorization codes. Zero
	// or negative falls back to [DefaultAuthCodeTTL].
	AuthCodeTTL time.Duration

	// InteractionTTL is the lifetime of persisted interaction records
	// and CSRF tokens. Zero or negative falls back to
	// [DefaultInteractionTTL].
	InteractionTTL time.Duration

	// RequireJARMResponseMode, when true, makes /authorize reject any
	// request that did not opt into one of the four JARM response_mode
	// values ("jwt", "query.jwt", "fragment.jwt", "form_post.jwt").
	// The flag implements the FAPI 2.0 Message Signing §5.5 mandate
	// that every authorize response be JARM-wrapped: a request that
	// omits the JARM response_mode is misconfigured against the active
	// profile, and the OP signals that with the OAuth wire code
	// "unsupported_response_mode" via the legacy redirect (JARM cannot
	// be used to convey "JARM is not in use yet"). The check runs only
	// after request validation has succeeded so a malformed request
	// surfaces its own error first; it has no effect when the request
	// already opted into JARM.
	RequireJARMResponseMode bool
}

// resolved is the post-default copy of [Deps] used during request handling.
// It is computed once per [Handler] invocation; the original Deps is left
// untouched so the caller's struct is read-only.
type resolved struct {
	Deps
}

// resolveDeps fills in defaults the caller chose to omit. The returned
// value is a fresh copy; the input is not mutated.
func resolveDeps(d Deps) resolved {
	if d.AuthCodeTTL <= 0 {
		d.AuthCodeTTL = DefaultAuthCodeTTL
	}
	if d.InteractionTTL <= 0 {
		d.InteractionTTL = DefaultInteractionTTL
	}
	if d.Driver == nil {
		d.Driver = interaction.JSONDriver{}
	}
	return resolved{Deps: d}
}

// now returns the wall-clock reading for this request, falling back to the
// system clock when [Deps.Clock] is nil.
func (r resolved) now() time.Time {
	if r.Clock == nil {
		return timex.SystemClock.Now()
	}
	return r.Clock.Now()
}

// Handler returns the HTTP handler the OP mounts at its authorize and
// interaction endpoints. The returned handler is safe for concurrent use;
// deps MUST NOT be mutated after the call.
//
// The function panics on a configuration that cannot satisfy the contract
// (nil store, nil codec). Callers should construct [Deps] from validated
// configuration so the panic path is unreachable in production.
func Handler(deps Deps) http.Handler {
	r := resolveDeps(deps)
	mux := http.NewServeMux()
	mux.Handle(r.AuthorizePath, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		serveAuthorize(w, req, r)
	}))
	mux.Handle(r.InteractionPath+"/{uid}", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		serveInteraction(w, req, r)
	}))
	return mux
}

// containsString reports whether haystack contains needle. The helper is a
// small readability win over slices.Contains in the request flow because
// the prompt / scope arrays are typed as []string already.
func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

// scopeIsSubset reports whether every element of want is present in have.
// Comparison is byte-equal because OAuth scope tokens are case-sensitive
// per RFC 6749 §3.3.
func scopeIsSubset(want, have []string) bool {
	for _, s := range want {
		if !containsString(have, s) {
			return false
		}
	}
	return true
}
