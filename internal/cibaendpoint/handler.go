package cibaendpoint

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/ciba"
	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/clientauth/clientauthhttp"
	"github.com/libraz/go-oidc-provider/internal/dpop"
	"github.com/libraz/go-oidc-provider/internal/mtls"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/store"
)

// auditClientAuthnFailure aliases the canonical event constant so
// the boundary helper and the local emission sites cannot drift.
const auditClientAuthnFailure = clientauthhttp.EventClientAuthnFailure

// Tunables the handler uses when [Deps] omits the corresponding
// field.
const (
	// authReqIDByteLength is the entropy of the wire auth_req_id.
	// 32 bytes (256 bits) matches the posture the library uses for
	// authorization codes, refresh tokens, and device codes — well
	// above any "guessing infeasible" bar.
	authReqIDByteLength = 32

	// maxFormBytes caps the size of a /bc-authorize request body.
	// The endpoint accepts only the form-encoded shape CIBA Core
	// §7.1 describes; a 64 KiB ceiling is far above any legitimate
	// request while bounding memory use against pathological
	// inputs (gosec G120).
	maxFormBytes = 64 * 1024
)

// Clock is the package-local view of the wall clock. It mirrors
// the device-authorization endpoint posture: a structurally-typed
// interface so a value satisfying [op.Clock] flows through without
// an explicit adapter, and a nil falls back to the system clock.
type Clock interface {
	Now() time.Time
}

// HintResolver maps a CIBA hint to a stable end-user subject.
// The library calls Resolve once per /bc-authorize POST after
// classifying the hint kind. Implementations MUST:
//
//   - return a non-empty subject on success;
//   - return [ErrUnknownUser] when the hint does not resolve to a
//     known end-user (the handler maps this to unknown_user_id);
//   - return any other error to surface as login_required (the
//     handler treats non-[ErrUnknownUser] failures as an
//     authentication failure rather than a soft "no such user"
//     answer).
type HintResolver interface {
	Resolve(ctx context.Context, kind ciba.HintKind, value string) (subject string, err error)
}

// ErrUnknownUser is the sentinel a [HintResolver] returns to signal
// the hint did not match a known end-user. Maps to the
// unknown_user_id wire code.
var ErrUnknownUser = errors.New("cibaendpoint: hint did not resolve to a known end-user")

// Deps bundles the runtime dependencies the /bc-authorize handler
// needs. The HTTP layer constructs a [Deps] once at startup and
// passes it to [Handler]; the handler is otherwise self-contained.
type Deps struct {
	// Issuer is the OP issuer URL. The handler stamps it onto the
	// audit stream.
	Issuer string

	// Clients is the read-only client registry. The handler looks
	// the authenticated client_id up before delegating to the
	// authenticator.
	Clients store.ClientStore

	// CIBARequests is the substore for CIBA records. The handler
	// writes a freshly minted record on every successful POST.
	CIBARequests store.CIBARequestStore

	// Clock supplies the current wall-clock reading. A nil Clock
	// falls back to [internal/timex.SystemClock].
	Clock Clock

	// SecretVerifier verifies confidential-client secrets. A nil
	// value installs the library default ([clientauth.Argon2id]).
	SecretVerifier clientauth.SecretVerifier

	// AssertionVerifier verifies private_key_jwt assertions. A
	// nil value disables private_key_jwt support.
	AssertionVerifier clientauth.AssertionVerifier

	// AllowedClientAuthMethods optionally restricts which client
	// authentication methods the endpoint accepts. Empty means
	// "no restriction"; non-empty means the chosen method must
	// appear in the list.
	AllowedClientAuthMethods []clientauth.Method

	// DPoP, when non-nil, makes /bc-authorize accept and verify a
	// "DPoP" header on the inbound POST. The verifier's
	// thumbprint is bound onto the persisted record so the
	// eventual /token request must present a proof signed with
	// the same key.
	DPoP *dpop.Verifier

	// DPoPNonces is the RFC 9449 §8 nonce issuer consulted on
	// the `use_dpop_nonce` challenge response.
	DPoPNonces dpop.NonceIssuer

	// MTLS, when non-nil, makes /bc-authorize stamp the SHA-256
	// thumbprint of the inbound mTLS leaf certificate onto the
	// persisted record so the eventual /token request is bound
	// to the same certificate per RFC 8705.
	MTLS *mtls.Verifier

	// RequireSenderConstraint, when true, makes the handler
	// reject any request that arrives without DPoP and without
	// mTLS. The flag is set by the FAPI 2.0 / FAPI-CIBA profile
	// so a deployment locked to sender-constrained tokens cannot
	// silently downgrade through CIBA flow.
	RequireSenderConstraint bool

	// HintResolver maps an inbound CIBA hint to a stable subject.
	// A nil resolver makes every request fail with login_required
	// — the embedder MUST wire a resolver for the endpoint to be
	// useful.
	HintResolver HintResolver

	// DefaultExpiresIn is the auth_req_id lifetime advertised on
	// the response when the client did not supply requested_expiry.
	// Zero or negative falls back to [ciba.DefaultExpiresIn].
	DefaultExpiresIn time.Duration

	// MaxExpiresIn is the upper bound the handler clamps a
	// requested_expiry value to. Zero disables clamping; a
	// non-zero value is the maximum auth_req_id lifetime the OP
	// will honour regardless of the client's request.
	MaxExpiresIn time.Duration

	// PollInterval is the value advertised to the client as
	// `interval`. Zero or negative falls back to
	// [ciba.DefaultInterval].
	PollInterval time.Duration

	// Audit is the structured audit-event sink. A nil emitter
	// falls back to [audit.Discard].
	Audit audit.Emitter
}

// auditEmitter returns the configured audit sink, or a
// [audit.Discard] emitter so call sites can invoke Emit
// unconditionally.
func (d *Deps) auditEmitter() audit.Emitter {
	if d.Audit == nil {
		return audit.Discard()
	}
	return d.Audit
}

// now returns the wall-clock reading for this request, falling
// back to the system clock when [Deps.Clock] is nil.
func (d *Deps) now() time.Time {
	if d.Clock == nil {
		return timex.SystemClock.Now()
	}
	return d.Clock.Now()
}

// effectiveExpiresIn returns the auth_req_id lifetime resolved
// against the default.
func (d *Deps) effectiveExpiresIn() time.Duration {
	if d.DefaultExpiresIn <= 0 {
		return ciba.DefaultExpiresIn
	}
	return d.DefaultExpiresIn
}

// pollInterval returns the advertised poll interval resolved
// against the default.
func (d *Deps) pollInterval() time.Duration {
	if d.PollInterval <= 0 {
		return ciba.DefaultInterval
	}
	return d.PollInterval
}

// successResponse is the CIBA Core §7.3 backchannel-authentication
// response body.
type successResponse struct {
	AuthReqID string `json:"auth_req_id"`
	ExpiresIn int64  `json:"expires_in"`
	Interval  int64  `json:"interval"`
}

// Handler returns the HTTP handler the OP mounts at its
// /bc-authorize endpoint. The returned handler is safe for
// concurrent use; deps MUST NOT be mutated after the call.
func Handler(deps Deps) http.Handler {
	resolved := resolveDeps(deps)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serve(w, r, resolved)
	})
}

// resolveDeps fills in defaults the caller chose to omit. The
// returned value is a fresh copy; the caller's [Deps] is not
// mutated.
func resolveDeps(d Deps) Deps {
	if d.SecretVerifier == nil {
		d.SecretVerifier = &clientauth.Argon2id{}
	}
	return d
}

// serve is the request-scoped entry point. It validates the
// request shape, authenticates the client, classifies the hint,
// resolves it to a subject, parses the requested parameters,
// mints the auth_req_id, and persists the resulting record.
func serve(w http.ResponseWriter, r *http.Request, deps Deps) {
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
	dpopJKT, ok := verifyDPoPProof(r, w, deps)
	if !ok {
		return
	}
	client, _, ok := authenticate(r.Context(), w, r, deps)
	if !ok {
		return
	}
	mtlsThumbprint := extractMTLSThumbprint(r, deps)
	if !enforceSenderConstraint(r.Context(), w, deps, dpopJKT, mtlsThumbprint, client.ID) {
		return
	}
	if !verifyClientGrantTypeAllowed(r.Context(), w, deps, client) {
		return
	}
	hintKind, hintValue, ok := classifyHint(r.Context(), w, deps, r.PostForm, client.ID)
	if !ok {
		return
	}
	subject, ok := resolveHint(r.Context(), w, deps, hintKind, hintValue, client.ID)
	if !ok {
		return
	}
	scope, ok := parseScope(r.Context(), w, deps, r.PostForm, client)
	if !ok {
		return
	}
	resource, ok := parseResource(w, r.PostForm)
	if !ok {
		return
	}
	acrValues := parseACRValues(r.PostForm.Get("acr_values"))
	bindingMessage, ok := parseBindingMessage(w, r.PostForm.Get("binding_message"))
	if !ok {
		return
	}
	expiresIn, ok := parseRequestedExpiry(w, r.PostForm.Get("requested_expiry"), deps)
	if !ok {
		return
	}
	userCode := strings.TrimSpace(r.PostForm.Get("user_code"))
	persist(r.Context(), w, deps, persistInput{
		Client:         client,
		Subject:        subject,
		HintKind:       hintKind,
		Scope:          scope,
		Resource:       resource,
		ACRValues:      acrValues,
		BindingMessage: bindingMessage,
		UserCode:       userCode,
		ExpiresIn:      expiresIn,
		DPoPJKT:        dpopJKT,
		MTLSThumbprint: mtlsThumbprint,
	})
}

// verifyDPoPProof inspects the request for a DPoP proof. When
// [Deps.DPoP] is nil or the request does not carry a proof, the
// returned thumbprint is empty and the handler proceeds. When the
// proof is present and verification fails, the function writes the
// RFC 9449 §8 envelope and returns ok=false.
func verifyDPoPProof(r *http.Request, w http.ResponseWriter, deps Deps) (string, bool) {
	if deps.DPoP == nil {
		return "", true
	}
	if r.Header.Get("DPoP") == "" {
		return "", true
	}
	res, err := deps.DPoP.VerifyHTTPRequest(r.Context(), r, "")
	if err != nil {
		dpop.WriteError(r.Context(), w, err, dpop.NonceSourceFromIssuer(deps.DPoPNonces))
		return "", false
	}
	return res.JKT, true
}

// authenticate resolves the client credentials carried by the
// request, looks the client up in the registry, and verifies the
// credentials. The helper delegates to a per-request
// [clientauthhttp.Authenticator] so /bc-authorize shares an
// identical authentication contract with the token, PAR, and
// device-authorization endpoints.
func authenticate(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	deps Deps,
) (*store.Client, *clientauth.Credentials, bool) {
	authenticator := clientauthhttp.Authenticator{
		Clients:           deps.Clients,
		SecretVerifier:    deps.SecretVerifier,
		AssertionVerifier: deps.AssertionVerifier,
		AllowedMethods:    deps.AllowedClientAuthMethods,
		Audit:             deps.auditEmitter(),
		AuditEventName:    auditClientAuthnFailure,
		AuditMessage:      "client authentication failed at backchannel-authentication endpoint",
	}
	return authenticator.Authenticate(ctx, w, r)
}

// extractMTLSThumbprint returns the SHA-256 thumbprint of the
// inbound mTLS leaf certificate. Returns an empty string when
// [Deps.MTLS] is nil, the request did not present a usable
// certificate, or the verifier could not parse one.
func extractMTLSThumbprint(r *http.Request, deps Deps) string {
	if deps.MTLS == nil {
		return ""
	}
	thumb, err := deps.MTLS.ThumbprintFromRequest(r)
	if err != nil {
		return ""
	}
	return thumb
}

// enforceSenderConstraint applies the FAPI 2.0 / FAPI-CIBA rule
// that no /bc-authorize request MAY produce a bearer token. When
// [Deps.RequireSenderConstraint] is true and the request carries
// neither DPoP nor mTLS, the function writes invalid_request and
// returns false.
func enforceSenderConstraint(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	dpopJKT, mtlsThumbprint, clientID string,
) bool {
	if !deps.RequireSenderConstraint {
		return true
	}
	if dpopJKT != "" || mtlsThumbprint != "" {
		return true
	}
	deps.auditEmitter().Emit(ctx, audit.Event{
		Name:     ciba.AuditAuthorizationUnboundRejected,
		Level:    audit.LevelWarn,
		Message:  "backchannel-authentication rejected: unbound request under sender-constraint profile",
		ClientID: clientID,
		Extras: map[string]any{
			"profile": "fapi2_baseline",
			"reason":  "unbound_request",
		},
	})
	writeError(w, http.StatusBadRequest, errInvalidRequest,
		"backchannel authentication requires DPoP or mTLS under the active profile")
	return false
}

// verifyClientGrantTypeAllowed rejects clients whose registered
// GrantTypes do not include the CIBA URN. The check matches the
// token-endpoint poll's gate so a misconfigured client cannot
// even initiate a CIBA flow.
func verifyClientGrantTypeAllowed(ctx context.Context, w http.ResponseWriter, deps Deps, client *store.Client) bool {
	if slices.Contains(client.GrantTypes, grant.CIBA.String()) {
		return true
	}
	deps.auditEmitter().Emit(ctx, audit.Event{
		Name:     ciba.AuditAuthorizationRejected,
		Level:    audit.LevelWarn,
		Message:  "backchannel-authentication rejected: client not registered for grant",
		ClientID: client.ID,
		Extras: map[string]any{
			"reason": "grant_type_not_permitted",
		},
	})
	writeError(w, http.StatusBadRequest, errUnauthorizedClient,
		"client is not authorized for the ciba grant")
	return false
}

// classifyHint dispatches to [ciba.ClassifyHint] and maps the
// sentinel onto the wire response. On success the helper returns
// the kind and the trimmed hint value.
func classifyHint(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	form url.Values,
	clientID string,
) (ciba.HintKind, string, bool) {
	kind, value, err := ciba.ClassifyHint(
		form.Get("login_hint"),
		form.Get("id_token_hint"),
		form.Get("login_hint_token"),
	)
	if err != nil {
		deps.auditEmitter().Emit(ctx, audit.Event{
			Name:     ciba.AuditAuthorizationRejected,
			Level:    audit.LevelWarn,
			Message:  "backchannel-authentication rejected: hint combination invalid",
			ClientID: clientID,
			Extras: map[string]any{
				"reason": "hint_combination_invalid",
			},
		})
		writeError(w, http.StatusBadRequest, errInvalidRequest,
			"exactly one of login_hint, id_token_hint, or login_hint_token is required")
		return ciba.HintNone, "", false
	}
	return kind, value, true
}

// resolveHint invokes the embedder's [HintResolver] and maps the
// outcome onto the wire response. A nil resolver collapses onto
// login_required so a misconfigured deployment never silently
// resolves every hint to the empty subject.
func resolveHint(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	kind ciba.HintKind,
	value, clientID string,
) (string, bool) {
	if deps.HintResolver == nil {
		deps.auditEmitter().Emit(ctx, audit.Event{
			Name:     ciba.AuditAuthorizationRejected,
			Level:    audit.LevelWarn,
			Message:  "backchannel-authentication rejected: no hint resolver configured",
			ClientID: clientID,
			Extras: map[string]any{
				"reason": "hint_resolution_failed",
			},
		})
		writeError(w, http.StatusBadRequest, errLoginRequired,
			"end-user authentication is required to resolve the hint")
		return "", false
	}
	subject, err := deps.HintResolver.Resolve(ctx, kind, value)
	if err != nil {
		if errors.Is(err, ErrUnknownUser) {
			deps.auditEmitter().Emit(ctx, audit.Event{
				Name:     ciba.AuditAuthorizationRejected,
				Level:    audit.LevelWarn,
				Message:  "backchannel-authentication rejected: unknown user",
				ClientID: clientID,
				Extras: map[string]any{
					"reason": "unknown_user_id",
				},
			})
			writeError(w, http.StatusBadRequest, errUnknownUserID,
				"the hint did not resolve to a known end-user")
			return "", false
		}
		deps.auditEmitter().Emit(ctx, audit.Event{
			Name:     ciba.AuditAuthorizationRejected,
			Level:    audit.LevelWarn,
			Message:  "backchannel-authentication rejected: hint resolution failed",
			ClientID: clientID,
			Extras: map[string]any{
				"reason": "hint_resolution_failed",
			},
		})
		writeError(w, http.StatusBadRequest, errLoginRequired,
			"end-user authentication is required to resolve the hint")
		return "", false
	}
	if subject == "" {
		deps.auditEmitter().Emit(ctx, audit.Event{
			Name:     ciba.AuditAuthorizationRejected,
			Level:    audit.LevelWarn,
			Message:  "backchannel-authentication rejected: resolver returned empty subject",
			ClientID: clientID,
			Extras: map[string]any{
				"reason": "hint_resolution_failed",
			},
		})
		writeError(w, http.StatusBadRequest, errLoginRequired,
			"end-user authentication is required to resolve the hint")
		return "", false
	}
	return subject, true
}

// parseScope dispatches to [ciba.ValidateScope] for the
// CIBA-specific "openid required" check, then validates the
// resulting subset against the client's registered Scopes.
func parseScope(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	form url.Values,
	client *store.Client,
) ([]string, bool) {
	scope, err := ciba.ValidateScope(form.Get("scope"))
	if err != nil {
		switch {
		case errors.Is(err, ciba.ErrMissingScope):
			writeError(w, http.StatusBadRequest, errInvalidRequest,
				"scope parameter is required")
		case errors.Is(err, ciba.ErrScopeMissingOpenID):
			deps.auditEmitter().Emit(ctx, audit.Event{
				Name:     ciba.AuditAuthorizationRejected,
				Level:    audit.LevelWarn,
				Message:  "backchannel-authentication rejected: scope missing openid",
				ClientID: client.ID,
				Extras: map[string]any{
					"reason": "scope_missing_openid",
				},
			})
			writeError(w, http.StatusBadRequest, errInvalidScope,
				"the openid scope value is required for ciba")
		default:
			writeError(w, http.StatusBadRequest, errInvalidRequest,
				"scope parameter is invalid")
		}
		return nil, false
	}
	allowed := make(map[string]struct{}, len(client.Scopes))
	for _, s := range client.Scopes {
		allowed[s] = struct{}{}
	}
	for _, s := range scope {
		if _, ok := allowed[s]; !ok {
			writeError(w, http.StatusBadRequest, errInvalidScope,
				"requested scope is not permitted for this client")
			return nil, false
		}
	}
	return slices.Clone(scope), true
}

// parseResource extracts the RFC 8707 resource indicators from the
// form. The function rejects relative URIs (RFC 8707 §2 mandates
// absolute) and normalises each value (lowercase scheme + host,
// trailing-slash stripped) so the persisted record carries the
// canonical form.
func parseResource(w http.ResponseWriter, form url.Values) ([]string, bool) {
	raw := form["resource"]
	if len(raw) == 0 {
		return nil, true
	}
	out := make([]string, 0, len(raw))
	for _, r := range raw {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		canonical, err := normaliseResource(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, errInvalidTarget,
				"resource parameter is not a valid absolute URI")
			return nil, false
		}
		out = append(out, canonical)
	}
	return out, true
}

// normaliseResource canonicalises a single resource indicator per
// RFC 8707 §2: lowercase scheme + host, trailing-slash stripped.
// Returns an error when the value is not an absolute URI.
func normaliseResource(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Scheme == "" || u.Host == "" {
		return "", errors.New("cibaendpoint: relative resource URI")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.Path = strings.TrimRight(u.Path, "/")
	return u.String(), nil
}

// parseACRValues splits the acr_values parameter on ASCII
// whitespace and returns the trimmed list. CIBA Core §7.1 carries
// the value verbatim onto the authentication device so the OP
// does not validate against a registered set; embedders perform
// the policy check inside their authentication-device callback.
func parseACRValues(raw string) []string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil
	}
	return strings.Fields(trimmed)
}

// parseBindingMessage dispatches to [ciba.ValidateBindingMessage]
// and maps the sentinel onto the wire response.
func parseBindingMessage(w http.ResponseWriter, raw string) (string, bool) {
	value, err := ciba.ValidateBindingMessage(raw)
	if err != nil {
		if errors.Is(err, ciba.ErrBindingMessageTooLong) {
			writeError(w, http.StatusBadRequest, errInvalidBindingMessage,
				"binding_message exceeds the OP-supported length")
			return "", false
		}
		writeError(w, http.StatusBadRequest, errInvalidBindingMessage,
			"binding_message is invalid")
		return "", false
	}
	return value, true
}

// parseRequestedExpiry dispatches to [ciba.ParseRequestedExpiry]
// and maps the sentinel onto the wire response. A zero return
// value means the client did not supply requested_expiry; the
// caller substitutes [Deps.effectiveExpiresIn].
func parseRequestedExpiry(
	w http.ResponseWriter,
	raw string,
	deps Deps,
) (time.Duration, bool) {
	value, err := ciba.ParseRequestedExpiry(raw, deps.MaxExpiresIn)
	if err != nil {
		writeError(w, http.StatusBadRequest, errInvalidRequest,
			"requested_expiry must be a positive integer")
		return 0, false
	}
	if value == 0 {
		return deps.effectiveExpiresIn(), true
	}
	return value, true
}

// persistInput bundles the parameters [persist] consumes. The
// struct exists to keep [serve]'s call site readable under the
// project's gocognit cap.
type persistInput struct {
	Client         *store.Client
	Subject        string
	HintKind       ciba.HintKind
	Scope          []string
	Resource       []string
	ACRValues      []string
	BindingMessage string
	UserCode       string
	ExpiresIn      time.Duration
	DPoPJKT        string
	MTLSThumbprint string
}

// persist mints the auth_req_id, writes the record, and emits the
// success envelope. Save collisions on the auth_req_id are treated
// as fatal randomness faults: the 256-bit space makes a collision
// inside an active record's TTL astronomically rare, so a single
// failure short-circuits to server_error rather than retrying.
func persist(ctx context.Context, w http.ResponseWriter, deps Deps, in persistInput) {
	authReqID, err := newAuthReqID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, errServerError, "could not allocate auth_req_id")
		return
	}
	now := deps.now().UTC()
	expiresAt := now.Add(in.ExpiresIn)
	interval := deps.pollInterval()
	rec := &store.CIBARequest{
		ID:             authReqID,
		ClientID:       in.Client.ID,
		Subject:        in.Subject,
		Scope:          in.Scope,
		Resource:       in.Resource,
		ACRValues:      in.ACRValues,
		BindingMessage: in.BindingMessage,
		UserCode:       in.UserCode,
		DPoPJKT:        in.DPoPJKT,
		MTLSCertS256:   in.MTLSThumbprint,
		Interval:       interval,
		IssuedAt:       now,
		ExpiresAt:      expiresAt,
		Status:         store.CIBARequestStatusPending,
	}
	if err := deps.CIBARequests.Save(ctx, rec); err != nil {
		writeError(w, http.StatusInternalServerError, errServerError, "could not persist ciba request")
		return
	}
	deps.auditEmitter().Emit(ctx, audit.Event{
		Name:     ciba.AuditAuthorizationIssued,
		Level:    audit.LevelInfo,
		Message:  "backchannel-authentication issued",
		ClientID: in.Client.ID,
		ActorID:  in.Subject,
		Extras: map[string]any{
			"client_id":  in.Client.ID,
			"scope":      append([]string(nil), in.Scope...),
			"resource":   append([]string(nil), in.Resource...),
			"expires_in": int64(in.ExpiresIn.Seconds()),
			"interval":   int64(interval.Seconds()),
			"binding":    bindingLabel(in.DPoPJKT, in.MTLSThumbprint),
			"hint_kind":  in.HintKind.String(),
		},
	})
	stampNoStore(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(successResponse{
		AuthReqID: authReqID,
		ExpiresIn: int64(in.ExpiresIn.Seconds()),
		Interval:  int64(interval.Seconds()),
	})
}

// newAuthReqID returns a freshly generated auth_req_id: 32 bytes
// of crypto/rand encoded as base64url-no-pad (256 bits of
// entropy). The body lives in this package rather than
// [internal/ciba] because the wire-secret path is owned by the
// issuer side; the helper packages stay free of HTTP / I/O
// concerns.
func newAuthReqID() (string, error) {
	buf := make([]byte, authReqIDByteLength)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("cibaendpoint: read random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// bindingLabel returns the audit-extras label naming which sender
// constraint the issued record carries: "dpop", "mtls", or
// "bearer".
func bindingLabel(dpopJKT, mtlsThumbprint string) string {
	switch {
	case dpopJKT != "":
		return "dpop"
	case mtlsThumbprint != "":
		return "mtls"
	default:
		return "bearer"
	}
}

// isFormContent reports whether ct is application/x-www-form-
// urlencoded, tolerating optional parameters (charset, boundary,
// etc.).
func isFormContent(ct string) bool {
	if ct == "" {
		return false
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.EqualFold(strings.TrimSpace(ct), "application/x-www-form-urlencoded")
}
