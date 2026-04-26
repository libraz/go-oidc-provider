package registrationendpoint

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/internal/scoperegistry"
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

// auditLogger is the structural audit-event sink. It is unexported so
// the public [Deps] surface does not expose the internal-only
// [auditEvent] shape. The op layer cannot wire a custom audit sink in
// v1.0; once an audit interface lands on the public op/ surface this
// can be promoted.
type auditLogger interface {
	Audit(ctx context.Context, ev auditEvent)
}

// auditEvent is the structural shape every DCR audit record carries.
// The names mirror docs/plans/002-product-design.md §A.6.2; new event
// names are added to the catalog in this file.
type auditEvent struct {
	// Name is the canonical event identifier, e.g.
	// "dcr.client.registered". Sinks routes records by this field.
	Name string

	// Level is the severity classification (info / warn / error).
	// Sinks may filter on this.
	Level string

	// Message is a short human-readable description for operators.
	Message string

	// ClientID is the client_id involved in the event, when known.
	// Empty for events that fire before a client is identified.
	ClientID string

	// Tag is the IAT tag (operator-supplied identifier) when the
	// event is bound to an IAT.
	Tag string
}

// Audit event names mirror docs/plans/002-product-design.md §A.6.2.
const (
	auditDCRIATConsumed           = "dcr.iat.consumed"
	auditDCRIATExpired            = "dcr.iat.expired"
	auditDCRIATInvalid            = "dcr.iat.invalid"
	auditDCROpenRegistrationUsed  = "dcr.open_registration_used"
	auditDCRClientRegistered      = "dcr.client.registered"
	auditDCRClientMetadataRead    = "dcr.client.metadata_read"
	auditDCRClientMetadataUpdated = "dcr.client.metadata_updated"
	auditDCRClientDeleted         = "dcr.client.deleted"
	auditDCRRATInvalid            = "dcr.rat.invalid"
	auditDCRMetadataValidation    = "dcr.metadata.validation_failed"

	auditLevelInfo = "info"
	auditLevelWarn = "warn"
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
	// falls back to [internal/timex.SystemClock].
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

	// ValidateMetadata is the embedder hook invoked after structural
	// validation passes and before the client is persisted. A non-nil
	// error rejects the registration with invalid_client_metadata;
	// the error message is sanitised before being returned to the
	// client.
	ValidateMetadata func(ctx context.Context, m ClientMetadata) error

	// Logger is the slog handler the endpoint emits diagnostic
	// records on. A nil Logger installs [slog.Default].
	Logger *slog.Logger
}

// Handler returns the HTTP handler the OP mounts at /register and
// /register/{client_id}. The returned handler is safe for concurrent
// use; deps MUST NOT be mutated after the call.
//
// The handler routes by method and path:
//
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

// logger returns the configured [*slog.Logger] or [slog.Default] when
// the caller did not supply one. The helper exists so handler code
// can call deps.logger().Warn(...) without nil-checks.
func (d *Deps) logger() *slog.Logger {
	if d.Logger == nil {
		return slog.Default()
	}
	return d.Logger
}

// audit returns the audit sink the handler uses. v1.0 ships a no-op
// sink; once the public op/ surface grows an audit interface, [Deps]
// will gain a field that this helper consults instead.
//
// The receiver is anonymous because v1.0 does not yet read any [Deps]
// field; call sites use the d.audit() shape so the migration path
// stays a one-line edit.
func (*Deps) audit() auditLogger { //nolint:ireturn // auditLogger is the package-internal interface call sites depend on; the concrete sink will swap once op/ exposes an audit hook.
	return noopAudit{}
}

// noopAudit is the zero-cost auditLogger used in v1.0 because the
// public op/ surface does not yet expose an audit hook. It exists so
// handler code can call deps.audit().Audit unconditionally without a
// nil-check.
type noopAudit struct{}

// Audit implements [auditLogger] as a no-op.
func (noopAudit) Audit(_ context.Context, _ auditEvent) {}

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
//
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
//
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

// isJSONContent reports whether ct is application/json, tolerating
// optional parameters (charset, etc.). Mirrors the helper in the
// token / par endpoints so the three surfaces stay aligned.
func isJSONContent(ct string) bool {
	if ct == "" {
		return false
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.EqualFold(strings.TrimSpace(ct), "application/json")
}
