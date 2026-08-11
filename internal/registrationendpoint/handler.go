package registrationendpoint

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/auditevent"
	internaljose "github.com/libraz/go-oidc-provider/internal/jose"
	"github.com/libraz/go-oidc-provider/internal/scoperegistry"
	"github.com/libraz/go-oidc-provider/internal/sector"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/store"
)

// Clock is the package-local view of the wall clock. It mirrors the
// token / authorize / par endpoint posture: a structurally-typed
// interface so a value satisfying [op.Clock] flows through without an
// explicit adapter, and a nil falls back to the system clock.
type Clock interface {
	Now() time.Time
}

// Audit event names. The strings here MUST agree with the public
// op.AuditEvent constants in op/audit.go; the registrationendpoint_test
// package contains a guard that compares both lists.
const (
	auditDCRIATConsumed           = string(auditevent.AuditDCRIATConsumed)
	auditDCRIATExpired            = string(auditevent.AuditDCRIATExpired)
	auditDCRIATInvalid            = string(auditevent.AuditDCRIATInvalid)
	auditDCROpenRegistrationUsed  = string(auditevent.AuditDCROpenRegistrationUsed)
	auditDCRClientRegistered      = string(auditevent.AuditDCRClientRegistered)
	auditDCRClientMetadataRead    = string(auditevent.AuditDCRClientMetadataRead)
	auditDCRClientMetadataUpdated = string(auditevent.AuditDCRClientMetadataUpdated)
	auditDCRClientDeleted         = string(auditevent.AuditDCRClientDeleted)
	auditDCRRATInvalid            = string(auditevent.AuditDCRRATInvalid)
	auditDCRMetadataValidation    = string(auditevent.AuditDCRMetadataValidation)
)

// Deps bundles the runtime dependencies the registration endpoint
// needs. The HTTP layer constructs a [Deps] once at startup and
// passes it to [Handler]; the handler is otherwise self-contained.
type Deps struct {
	// Issuer is the OP issuer URL. It is written into the
	// WWW-Authenticate realm on 401 responses and into the
	// registration_client_uri so RPs can locate the management
	// endpoint.
	Issuer string

	// MountPrefix is the URL prefix the OP mounts under, e.g.
	// "/oidc". It is concatenated with [RegisterPath] to compute the
	// path component of registration_client_uri.
	MountPrefix string

	// RegisterPath is the relative path the registration endpoint is
	// mounted at, e.g. "/register". The handler routes
	// /register/{client_id} for management and the bare path for new
	// registrations.
	RegisterPath string

	// Clock supplies the current wall-clock reading. A nil Clock
	// falls back to [timex.SystemClock].
	Clock Clock

	// Clients is the read-write client registry. The registration
	// endpoint requires write access; backends that implement only
	// [store.ClientStore] are rejected by op.New before reaching
	// this handler.
	Clients store.ClientRegistry

	// InitialAccessTokens is the IAT substore. The handler reads it
	// to verify the bearer credential on POST /register and writes
	// to it via IncrementUses on a successful registration.
	InitialAccessTokens store.InitialAccessTokenStore

	// RegistrationAccessTokens is the RAT substore. The handler
	// writes a freshly minted RAT on POST /register and rotates it
	// on PUT /register/{client_id}.
	RegistrationAccessTokens store.RegistrationAccessTokenStore

	// Scopes is the read-only scope registry. A nil value disables
	// only the per-scope IsRegistered allowlist check; the IAT-bound
	// AllowedScopes filter still runs.
	Scopes *scoperegistry.Registry

	// Open, when true, allows POST /register without an IAT. Open
	// registration emits a per-request WARN log.
	Open bool

	// OpenRegistrationDefaultScopes is the scope list applied as the
	// default when an open-registration POST omits the scope field.
	// A nil/empty slice means "no default" — clients that did not
	// request scope are persisted with [store.Client.Scopes] empty,
	// and any subsequent /authorize request that spells out scopes
	// the client did not register for is rejected as invalid_scope.
	//
	// The IAT-bound path is unaffected: when an IAT is presented
	// without [store.InitialAccessToken.AllowedScopes] the default
	// remains the registry's public scope list (the IAT issuer is
	// trusted operator code, so the broader default is acceptable
	// there).
	OpenRegistrationDefaultScopes []string

	// AllowedGrantTypes whitelists the grant_types a registration
	// may request. Empty applies the library default {auth code,
	// refresh}. The op layer resolves this before threading the
	// value in, so the handler always sees a concrete list.
	AllowedGrantTypes []string

	// AllowedResponseTypes whitelists the response_types a
	// registration may request. Empty applies {"code"} as the
	// library default.
	AllowedResponseTypes []string

	// PairwiseEnabled reports whether [op.WithPairwiseSubject] was
	// configured. When false, "subject_type": "pairwise" is
	// rejected.
	PairwiseEnabled bool

	// AllowLocalhostLoopback widens the RFC 8252 §7.3 loopback
	// carve-out applied to redirect_uri values to admit the textual
	// "localhost" host in addition to the 127.0.0.1 and [::1] IP
	// literals. The default false rejects the textual host so a
	// DNS-rebinding adversary (RFC 8252 §8.3) cannot pivot a
	// registered http://localhost:* URI onto a host they control.
	// Embedders flip the bit by passing
	// [op.WithAllowLocalhostLoopback] at construction.
	AllowLocalhostLoopback bool

	// AllowInsecureBackchannelLogoutForDev admits plain-http
	// loopback URLs (127.0.0.1, [::1], localhost) for the
	// `backchannel_logout_uri` field at static-client and DCR
	// validation time. The default false enforces the
	// OpenID Connect Back-Channel Logout 1.0 §2.2 https-only rule.
	// Embedders flip the bit by passing
	// [op.WithAllowInsecureBackchannelLogoutForDev] for dev/CI
	// fixtures only — production deployments leave it off.
	AllowInsecureBackchannelLogoutForDev bool

	// JWEPolicy narrows the JWE alg / enc values a registration may
	// declare below the internal/jose allow-list. The zero value
	// leaves the full allow-list in force. The op layer populates it
	// from [op.WithSupportedEncryptionAlgs] so a client cannot register
	// an algorithm the OP has been configured to refuse — which the
	// runtime would otherwise reject on the client's first encrypted
	// exchange.
	JWEPolicy internaljose.JWEPolicy

	// SectorResolver is the SSRF-defended sector_identifier_uri fetcher
	// the validator drives at registration time (OIDC Core 1.0 §5 /
	// §8.1). A nil value falls back to a zero-config [sector.Resolver]
	// so internal tests that exercise the validator without going
	// through op.New still see the production posture; the op layer
	// always supplies an explicit resolver pre-wired with the embedder
	// configuration (clock, AllowPrivateNetwork opt-in, custom HTTP
	// client for testkit fronting).
	SectorResolver *sector.Resolver

	// ValidateMetadata is the embedder hook invoked after structural
	// validation passes and before the client is persisted. A non-nil
	// error rejects the registration with invalid_client_metadata;
	// the error message is sanitised before being returned to the
	// client.
	ValidateMetadata func(ctx context.Context, m ClientMetadata) error

	// Logger is the slog handler the endpoint emits diagnostic
	// records on. A nil Logger installs [slog.Default()].
	Logger *slog.Logger

	// Audit is the structured audit-event sink. A nil Emitter
	// collapses to [audit.Discard()] so handler code can call
	// deps.audit().Emit unconditionally without a nil-check.
	Audit audit.Emitter

	// OnClientDeleted is the optional cascade hook the handler invokes
	// after a successful DELETE /register/{client_id}. It runs in the
	// request goroutine after the in-tree cascade (see [Deps.RefreshTokens]
	// / [Deps.Grants]) and before the 204 is written. The library
	// invokes [store.RevokeByClient] on every supplied substore that
	// implements the optional interface; the hook lets the embedder
	// extend the cascade to records the library does not own (cached
	// userinfo, sessions held outside the OP, custom audit pipelines).
	// A non-nil error is logged but does not abort the response — the
	// client record is already gone, and surfacing the error to the RP
	// would imply a recoverable failure that the embedder cannot retry.
	OnClientDeleted func(ctx context.Context, clientID string) error

	// RefreshTokens is the optional refresh-token substore the handler
	// probes for [store.RevokeByClient] during the delete cascade. A
	// nil substore opts out of the in-tree cascade for refresh tokens;
	// the embedder's [OnClientDeleted] hook takes over.
	RefreshTokens store.RefreshTokenStore

	// Grants is the optional grant substore the handler probes for
	// [store.RevokeByClient] during the delete cascade. A nil substore
	// opts out of the in-tree cascade for grants.
	Grants store.GrantStore

	// AccessTokens is the optional JWT access-token registry the
	// handler probes for [store.RevokeByClient] during the delete
	// cascade. A nil substore opts out of the in-tree JWT-AT
	// cascade; the embedder's [OnClientDeleted] hook takes over.
	AccessTokens store.AccessTokenRegistry

	// OpaqueAccessTokens is the optional opaque access-token substore
	// the handler probes for [store.RevokeByClient] during the delete
	// cascade. A nil substore opts out of the in-tree opaque-AT
	// cascade.
	OpaqueAccessTokens store.OpaqueAccessTokenStore
}

// Handler returns the HTTP handler the OP mounts at /register and
// /register/{client_id}. The returned handler is safe for concurrent
// use; deps MUST NOT be mutated after the call.
// The handler routes by method and path:
//   - POST <RegisterPath>             -> handleRegister (RFC 7591 §3)
//   - GET  <RegisterPath>/{client_id} -> handleRead    (RFC 7592 §2.1)
//   - PUT  <RegisterPath>/{client_id} -> handleUpdate  (RFC 7592 §2.2)
//   - DELETE ditto                    -> handleDelete  (RFC 7592 §2.3)
//
// The OP mounts the handler at both <RegisterPath> and
// <RegisterPath>/ so http.ServeMux dispatches both forms; the handler
// distinguishes them by inspecting the trailing path segment.
func Handler(deps Deps) http.Handler {
	resolved := resolveDeps(deps)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serve(w, r, resolved)
	})
}

// resolveDeps fills in defaults the caller chose to omit. The
// returned value is a fresh copy; the caller's [Deps] is not mutated.
func resolveDeps(d Deps) Deps {
	if len(d.AllowedGrantTypes) == 0 {
		d.AllowedGrantTypes = []string{"authorization_code", "refresh_token"}
	}
	if len(d.AllowedResponseTypes) == 0 {
		d.AllowedResponseTypes = []string{"code"}
	}
	return d
}

// now returns the wall-clock reading for this request, falling back
// to the system clock when [Deps.Clock] is nil.
func (d *Deps) now() time.Time {
	if d.Clock == nil {
		return timex.SystemClock.Now()
	}
	return d.Clock.Now()
}

// logger returns the configured [*slog.Logger] or [slog.Default()] when
// the caller did not supply one. The helper exists so handler code
// can call deps.logger().Warn(...) without nil-checks.
func (d *Deps) logger() *slog.Logger {
	if d.Logger == nil {
		return slog.Default()
	}
	return d.Logger
}

// audit returns the audit sink the handler uses. A nil [Deps.Audit]
// collapses to [audit.Discard()] so handler code can call
// deps.audit().Emit unconditionally without a nil-check.
func (d *Deps) audit() audit.Emitter {
	if d.Audit == nil {
		return audit.Discard()
	}
	return d.Audit
}

// serve routes the request to the matching method+path handler. The
// op layer mounts the handler at both <RegisterPath> and
// <RegisterPath>/{client_id} so the routing logic here only has to
// distinguish the two shapes.
func serve(w http.ResponseWriter, r *http.Request, deps Deps) {
	clientID, isManagement := managementClientID(r.URL.Path, deps.MountPrefix, deps.RegisterPath)
	if isManagement {
		serveManagement(w, r, deps, clientID)
		return
	}
	serveRegistration(w, r, deps)
}

// serveRegistration routes the bare-/register path. POST is the only
// admitted verb; everything else collapses onto 405.
func serveRegistration(w http.ResponseWriter, r *http.Request, deps Deps) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		stampNoStore(w)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	handleRegister(w, r, deps)
}

// serveManagement routes the /register/{client_id} sub-paths. GET /
// PUT / DELETE are the admitted verbs; everything else returns 405.
func serveManagement(w http.ResponseWriter, r *http.Request, deps Deps, clientID string) {
	switch r.Method {
	case http.MethodGet:
		handleRead(w, r, deps, clientID)
	case http.MethodPut:
		handleUpdate(w, r, deps, clientID)
	case http.MethodDelete:
		handleDelete(w, r, deps, clientID)
	default:
		w.Header().Set("Allow", "GET, PUT, DELETE")
		stampNoStore(w)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// managementClientID extracts the {client_id} path parameter for the
// RFC 7592 management endpoints. The function returns ("", false) when
// the request targets the bare /register path and (id, true) when it
// targets /register/{id}.
// The op layer routes /register and /register/{client_id} to the same
// handler instance via two http.ServeMux entries; this helper does
// the second-stage discrimination.
func managementClientID(path, mountPrefix, registerPath string) (string, bool) {
	full := joinPath(mountPrefix, registerPath)
	if !strings.HasPrefix(path, full) {
		return "", false
	}
	rest := strings.TrimPrefix(path, full)
	if rest == "" || rest == "/" {
		return "", false
	}
	if !strings.HasPrefix(rest, "/") {
		return "", false
	}
	id := strings.TrimPrefix(rest, "/")
	// Reject embedded slashes — the {client_id} parameter is opaque
	// and must not contain path separators.
	if strings.ContainsAny(id, "/?#") {
		return "", false
	}
	return id, true
}

// joinPath concatenates mountPrefix and endpoint into a full path,
// matching the rule applied in op/op.go so the handler computes the
// same absolute path the router mounts under.
func joinPath(mountPrefix, endpoint string) string {
	if mountPrefix == "/" || mountPrefix == "" {
		return endpoint
	}
	return mountPrefix + endpoint
}

// registrationClientURI returns the registration_client_uri value the
// OP advertises in successful registration responses. The URL is
// formed by joining issuer + mountPrefix + registerPath + clientID.
// The Issuer is the canonical anchor on purpose: RFC 7592 §2 mandates
// that the URL be reachable by the RP, and the OP advertises a single
// stable Issuer through discovery. Tests that drive the handler via
// httptest.NewServer therefore see a URI rooted at the configured
// Issuer rather than the random ephemeral host the test server
// listens on; that mismatch is expected, and the test fixtures rewrite
// the path before issuing follow-up requests (see manage_test.go).
func registrationClientURI(issuer, mountPrefix, registerPath, clientID string) string {
	issuer = strings.TrimRight(issuer, "/")
	prefix := mountPrefix
	if prefix == "/" || prefix == "" {
		prefix = ""
	} else {
		prefix = strings.TrimRight(prefix, "/")
	}
	if !strings.HasPrefix(registerPath, "/") {
		registerPath = "/" + registerPath
	}
	return issuer + prefix + registerPath + "/" + clientID
}
