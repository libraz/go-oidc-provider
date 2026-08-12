package authorizeendpoint

import (
	"context"
	"net/http"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/internal/clientencjwks"
	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/csrf"
	"github.com/libraz/go-oidc-provider/internal/i18n"
	"github.com/libraz/go-oidc-provider/internal/jar"
	"github.com/libraz/go-oidc-provider/internal/jarm"
	"github.com/libraz/go-oidc-provider/internal/proxy"
	"github.com/libraz/go-oidc-provider/internal/scoperegistry"
	"github.com/libraz/go-oidc-provider/internal/sessions"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
)

// ACRResolveInput is the bundle the wire layer hands to [Deps.ACRResolver]
// when terminating an interaction. It carries the authorize request's
// requested acr_values, the LoginFlow's completed-step kinds, the
// internal AAL the ceremony reached, and the (subject, client) pair so
// a custom [op.ACRPolicy] can build a public LoginContext at the
// adapter layer.
type ACRResolveInput struct {
	RequestedACRValues []string
	CompletedKinds     []string
	InternalAAL        authn.AAL
	Subject            string
	ClientID           string
	RequestedScopes    []string
	RemoteIP           string
	UserAgent          string
	AcceptLanguage     string
}

// ACRResolveOutput is the policy verdict the wire layer applies before
// stamping acr / amr onto the persisted grant. ok=false signals the
// policy could not satisfy any requested acr, so the issuer omits the
// claim entirely. ok=true with a nil AMR keeps the per-factor RFC
// 8176 aggregation in place; a non-nil AMR replaces it verbatim.
type ACRResolveOutput struct {
	ACR string
	AMR []string
	OK  bool
}

// ACRResolver bridges the public [op.ACRPolicy] seam to the wire layer.
// The library wires a non-nil resolver from the configured policy at
// op.New time; tests that exercise the authorize endpoint directly may
// leave the field nil to preserve the legacy behaviour (the
// per-factor aggregator's acr / amr flow through unchanged).
type ACRResolver func(ctx context.Context, in ACRResolveInput) ACRResolveOutput

// Default timing budgets the handler uses when [Deps] does not override
// them. The interaction cookie lifetime mirrors the cookie profile
// configured in internal/cookie; the authorization-code TTL matches
// the OAuth code-flow short-lived posture.
const (
	// DefaultAuthCodeTTL is the lifetime of an issued authorization code.
	// 60 seconds is well below the RFC 6749 §4.1.2 ceiling and matches
	// the FAPI 2.0 baseline.
	DefaultAuthCodeTTL = 60 * time.Second

	// DefaultInteractionTTL is the lifetime of an interaction record.
	// One hour matches the [cookie.InteractionProfile] MaxAge so
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
// internal/tokenendpoint so a value satisfying [op.Clock] flows through
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

	// Transactions commits Grant, PAR, and Authorization Code mutations
	// atomically at authorization completion. The public op.New wiring
	// requires this capability whenever the authorization-code grant is
	// enabled.
	Transactions store.Transactional

	// Grants is the consent substore. The handler reads (subject, client)
	// to decide whether a re-consent prompt is required and writes a
	// fresh grant when consent succeeds.
	Grants store.GrantStore

	// ExtensionPolicy configures the gates that run after the request
	// itself validates: RFC 9396 authorization_details, the Grant
	// Management draft parameters, and the RFC 9449 §10.1 "dpop_jkt"
	// commitment. The value is taken whole rather than reassembled from
	// per-flag fields so /authorize and /par cannot be handed different
	// policies — they are consecutive gates on the same request, and a
	// rule that fires at only one of them mints a request_uri the next
	// gate refuses.
	ExtensionPolicy authorize.ExtensionPolicy

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

	// CompletionKey derives stable, domain-separated IDs for resumable
	// authorization completion. The public wiring derives it from the
	// active cookie key; it must contain at least 32 bytes.
	CompletionKey []byte

	// CSRF is the HMAC signer for double-submit tokens.
	CSRF *csrf.Signer

	// InteractionOrigins is the Origin / Referer allowlist enforced on
	// every state-changing /interaction request.
	//
	// It is deliberately NOT the OP's CORS allowlist. That list also
	// carries the origin of every registered client's redirect_uri, so
	// reusing it here would let an origin registered by one client post
	// to another client's consent ceremony. The interaction endpoint is
	// reached from the OP's own login UI (same origin as the issuer) or,
	// when the embedder hosts that UI elsewhere, from an origin the
	// embedder enumerated explicitly — nothing derived from a client
	// registration belongs in it.
	InteractionOrigins *csrf.Allowlist

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
	// trailing slash. When [Deps.SPALoginMount] is set this value is
	// only used as the redirect target fallback for legacy callers that
	// have not opted into the SPA wiring; the JSON state surface moves
	// under [Deps.SPALoginMount].
	InteractionPath string

	// SPALoginMount, when non-empty, replaces the legacy
	// /interaction/{uid} surface with a SPA-friendly mount tree:
	//
	//   GET    SPALoginMount/{uid}             — SPA shell (index.html)
	//   GET    SPALoginMount/state/{uid}       — prompt JSON
	//   POST   SPALoginMount/state/{uid}       — submission
	//   DELETE SPALoginMount/state/{uid}       — cancel
	//   GET    SPALoginMount/assets/{path...}  — static asset fan-out
	//
	// The shell + asset routes are mounted only when [Deps.SPAStaticDir]
	// is also set; an empty StaticDir leaves shell + assets unmounted
	// (the embedder serves the SPA externally) but the redirect target
	// and the /state JSON surface still move under SPALoginMount.
	// MUST NOT carry a trailing slash. MUST NOT collide with
	// [Deps.AuthorizePath] or any other OP-mounted route — the wiring
	// layer enforces the disjointness check before constructing Deps.
	SPALoginMount string

	// SPAStaticDir, when non-empty, is the on-disk directory the
	// handler serves the SPA bundle from. The handler reads it
	// through a hardened [http.FileSystem] wrapper that:
	//
	//   - rejects basename entries beginning with "." (dotfiles)
	//   - returns "not found" for directory targets without an
	//     index.html sibling (no auto-listing)
	//   - rejects symlinks whose target lies outside the root
	//
	// An empty value disables shell + asset serving; only the
	// /state JSON routes are mounted.
	SPAStaticDir string

	// Clock supplies the current wall-clock reading. A nil value falls
	// back to [timex.SystemClock].
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

	// RequestPolicy carries the profile-conditional requirements
	// [authorize.Request.Validate] enforces: whether PKCE, a nonce, or
	// at least one of state / nonce is mandatory, and whether the
	// "openid" scope may be omitted. Like [Deps.ExtensionPolicy] the
	// value is taken whole so /par validates every request against the
	// same policy /authorize will apply to it moments later.
	RequestPolicy authorize.Policy

	// RequirePAR, when true, makes /authorize reject any request that
	// did not arrive via a [RFC 9126] pushed authorization request_uri.
	// Bare-wire-form requests (client_id + redirect_uri + response_type
	// in the URL) and JAR-only requests (request=<JWT> without a PAR
	// request_uri) both surface invalid_request. FAPI 2.0 §5.3.1
	// upgrades RFC 9126's optional opt-in to a MUST; vanilla OIDC Core
	// deployments leave this false so the legacy path keeps working.
	RequirePAR bool

	// Issuer is the OP's canonical issuer URL. The handler stamps it
	// onto every /authorize response (success and error) as the
	// RFC 9207 "iss" parameter — defense-in-depth against mix-up
	// attacks and a FAPI 2.0 §5.3.2.2 MUST. An empty value disables
	// the emission so vanilla OIDC Core deployments that have not
	// adopted RFC 9207 keep the legacy wire shape.
	Issuer string

	// AllowPrivateNetworkJAR disables the SSRF deny-list applied to a
	// JAR request_uri before the OP fetches the request object. The
	// default posture rejects loopback / link-local / RFC 1918 hosts;
	// embedders that front their RPs with private DNS opt in via
	// op.WithAllowPrivateNetworkJAR.
	AllowPrivateNetworkJAR bool

	// ClaimsParameterEnabled, when false, makes /authorize discard
	// any parsed OIDC Core 1.0 §5.5 "claims" payload before the
	// snapshot is persisted. The library default is true (the wiring
	// layer leaves the field at zero value when the embedder calls
	// op.WithClaimsParameterSupported(true) or omits the option
	// entirely; op.WithClaimsParameterSupported(false) flips this to
	// false on the wire layer). The parser still rejects a malformed
	// payload so the wire shape stays uniform with FAPI 2.0; the
	// flag only governs whether the (validated) payload survives
	// onto the grant for downstream projection.
	ClaimsParameterEnabled bool

	// ACRResolver, when non-nil, is consulted before stamping acr /
	// amr onto the persisted grant. The library wires a non-nil
	// resolver from the [op.ACRPolicy] supplied via [op.WithACRPolicy]
	// (defaulting to [op.DefaultACRPolicy]); tests that exercise the
	// authorize endpoint directly may leave the field nil to preserve
	// the legacy wire shape (the aggregator's acr / amr flow through
	// unchanged).
	ACRResolver ACRResolver

	// LocaleResolver, when non-nil, walks the locale priority chain
	// (PreferredLocaleStore → ui_locales → __Host-oidc_locale cookie
	// → Accept-Language → default) and stamps the result onto every
	// rendered [interaction.Prompt] (Locale / UILocalesHint /
	// LocalesAvailable). A nil value leaves the prompt's locale
	// fields empty — useful for unit tests that drive the handler
	// directly without an i18n subsystem.
	LocaleResolver *i18n.Resolver

	// ProxyTrust, when non-nil, governs how the authorize endpoint
	// resolves [http.Request.RemoteAddr] / scheme / host through
	// X-Forwarded-* headers. The trust is consulted on every authorize
	// request; values arriving from a CIDR outside the trust skip
	// header consultation (the request's RemoteAddr is treated as the
	// authoritative client IP). A nil trust disables forwarded-header
	// processing entirely — the legacy posture before
	// [op.WithTrustedProxies] was wired through.
	ProxyTrust *proxy.Trust

	// ClientEncJWKs resolves the RP's encryption recipient when the
	// client registered authorization_encrypted_response_alg / _enc
	// (JARM with JWE wrap; JARM by default emits a signed JWT). A
	// nil value disables outbound JARM encryption; clients that
	// registered the metadata still see signed JARM responses, which
	// the validator rejects at registration time when both halves are
	// configured but the OP cannot honour the wrap.
	ClientEncJWKs *clientencjwks.Resolver

	// FirstPartyClients is the set of client_id values the embedder
	// marked as first party via [op.WithFirstPartyClients]. When the
	// dispatcher would otherwise prompt for consent, a client whose
	// id appears here AND whose [store.Client.Source] is
	// [store.ClientSourceStatic] or [store.ClientSourceAdmin] gets an
	// auto-grant covering the requested scope, followed by a silent
	// authorization-code mint. Dynamic-source clients (RFC 7591) are
	// excluded structurally — the wiring layer never adds them. When
	// the request carries prompt=consent the skip is suppressed (the
	// RP explicitly asked for re-consent), and FAPI 2.0 profiles
	// reject the option at construction time so this field is empty
	// under those profiles.
	FirstPartyClients map[string]struct{}

	// Audit is the [audit.Emitter] the handler raises events on. The
	// authorize surface emits [op.AuditConsentGrantedFirstParty]
	// when the first-party skip applies. A nil value collapses
	// every emit to a no-op, matching the rest of the code base.
	Audit audit.Emitter
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

// spaActive reports whether the handler is wired for the SPA mount
// tree. Callers branch on this to choose between the legacy
// /interaction/{uid} surface and the SPA-friendly shell + state +
// asset layout.
func (r resolved) spaActive() bool {
	return r.SPALoginMount != ""
}

// authorizeRedirectBase returns the path prefix /authorize emits a
// 302 against; the handler appends "/" + uid. The SPA wiring takes
// precedence when active; otherwise the legacy /interaction prefix
// stands.
func (r resolved) authorizeRedirectBase() string {
	if r.spaActive() {
		return r.SPALoginMount
	}
	return r.InteractionPath
}

// now returns the wall-clock reading for this request, falling back to the
// system clock when [Deps.Clock] is nil.
func (r resolved) now() time.Time {
	if r.Clock == nil {
		return timex.SystemClock.Now()
	}
	return r.Clock.Now()
}

// isFirstPartyClient reports whether clientID was registered as first
// party via [op.WithFirstPartyClients]. The membership lookup runs in
// O(1) because the wiring layer materialises the slice into a set.
func (r resolved) isFirstPartyClient(clientID string) bool {
	if len(r.FirstPartyClients) == 0 {
		return false
	}
	_, ok := r.FirstPartyClients[clientID]
	return ok
}

// auditEmitter returns a non-nil [audit.Emitter]. A zero-value Deps gets
// the no-op emitter so the handler can call audit() unconditionally
// without per-call nil checks.
func (r resolved) auditEmitter() audit.Emitter {
	if r.Audit == nil {
		return audit.Discard()
	}
	return r.Audit
}

// Handler returns the HTTP handler the OP mounts at its authorize and
// interaction endpoints. The returned handler is safe for concurrent use;
// deps MUST NOT be mutated after the call.
// The function panics on a configuration that cannot satisfy the contract
// (nil store, nil codec). Callers should construct [Deps] from validated
// configuration so the panic path is unreachable in production.
func Handler(deps Deps) http.Handler {
	r := resolveDeps(deps)
	mux := http.NewServeMux()
	mux.Handle(r.AuthorizePath, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		serveAuthorize(w, req, r)
	}))
	if r.spaActive() {
		registerSPARoutes(mux, r)
	} else {
		mux.Handle(r.InteractionPath+"/{uid}", http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			serveInteraction(w, req, r)
		}))
	}
	return mux
}

// registerSPARoutes installs the SPA-friendly route tree under
// [Deps.SPALoginMount]. The state-endpoint patterns put the literal
// "state" at the first path segment (LoginMount/state/{uid}) so the
// route shapes are pairwise disjoint with the shell pattern
// (LoginMount/{uid}) and the asset pattern
// (LoginMount/assets/{path...}); a state path under
// LoginMount/{uid}/state would collide with assets at the
// "/{uid}=assets, /state=path" overlap and panic at mux
// registration. When [Deps.SPAStaticDir] is empty the shell + asset
// registrations are suppressed; the embedder is then responsible
// for rendering the SPA at SPALoginMount/{uid}.
func registerSPARoutes(mux *http.ServeMux, r resolved) {
	statePath := r.SPALoginMount + "/state/{uid}"
	stateHandler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		// The SPA fetch path cannot follow the cross-origin RP-callback
		// redirect that the orchestrator emits at chain termination
		// (fetch with redirect:"follow" exposes the response as opaque,
		// and redirect:"manual" hides the Location header). Wrap the
		// writer so a 302 is rewritten as a JSON terminal envelope the
		// SPA can consume with window.location.href = location.
		tw := newSPATerminalWriter(w)
		serveInteraction(tw, req, r)
		tw.flush()
	})
	mux.Handle("GET "+statePath, stateHandler)
	mux.Handle("POST "+statePath, stateHandler)
	mux.Handle("DELETE "+statePath, stateHandler)
	if r.SPAStaticDir == "" {
		return
	}
	shell := newSPAShellHandler(r)
	assets := newSPAAssetHandler(r)
	mux.Handle("GET "+r.SPALoginMount+"/{uid}", shell)
	mux.Handle("GET "+r.SPALoginMount+"/assets/{path...}", assets)
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
