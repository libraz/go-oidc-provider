package devicecodeendpoint

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
	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/clientauth/clientauthhttp"
	"github.com/libraz/go-oidc-provider/internal/devicecode"
	"github.com/libraz/go-oidc-provider/internal/dpop"
	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/internal/httpx"
	"github.com/libraz/go-oidc-provider/internal/mtls"
	"github.com/libraz/go-oidc-provider/internal/resourceindicator"
	"github.com/libraz/go-oidc-provider/internal/scoperegistry"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/store"
)

// auditClientAuthnFailure aliases the canonical event constant so
// the boundary helper and the local emission sites cannot drift.
const auditClientAuthnFailure = clientauthhttp.EventClientAuthnFailure

// Tunables the handler uses when [Deps] omits the corresponding
// field. The defaults match the values documented in ADR 0031 §Q3.
const (
	// deviceCodeByteLength is the entropy of the wire device_code.
	// 32 bytes (256 bits) is the same posture the library uses for
	// authorization codes and refresh tokens, well above the §3.2
	// "guessing infeasible" requirement.
	deviceCodeByteLength = 32

	// maxFormBytes caps the size of a /device_authorization request
	// body. The endpoint accepts only the form-encoded shape RFC
	// 8628 §3.1 describes; a 64 KiB ceiling is far above any
	// legitimate request while bounding memory use against
	// pathological inputs (gosec G120).
	maxFormBytes = 64 * 1024

	// userCodeRetryBudget bounds how many user_code regeneration
	// attempts the handler performs before giving up on a
	// collision. Reaching the budget is treated as a fatal
	// randomness fault — the 40-bit user_code space is large
	// enough that collisions inside an active record's TTL are
	// astronomically rare.
	userCodeRetryBudget = 8
)

//nolint:gochecknoglobals // immutable RFC 8628 single-valued parameter allowlist.
var deviceAuthSingleValuedParams = []string{
	"client_id",
	"client_secret",
	"client_assertion",
	"client_assertion_type",
	"scope",
}

// Clock is the package-local view of the wall clock. It mirrors
// the token / par endpoint posture: a structurally-typed interface
// so a value satisfying [op.Clock] flows through without an
// explicit adapter, and a nil falls back to the system clock.
type Clock interface {
	Now() time.Time
}

// Deps bundles the runtime dependencies the
// /device_authorization handler needs. The HTTP layer constructs
// a [Deps] once at startup and passes it to [Handler]; the
// handler is otherwise self-contained.
type Deps struct {
	// Issuer is the OP issuer URL. The handler stamps it onto the
	// audit stream and uses it as the default base for the
	// verification URI when [VerificationURI] is empty.
	Issuer string

	// VerificationURI overrides the default `<issuer>/device`
	// verification page URL. When empty the handler synthesises
	// the default from [Issuer].
	VerificationURI string

	// Clients is the read-only client registry. The handler
	// looks the authenticated client_id up before delegating to
	// [authn].
	Clients store.ClientStore

	// DeviceCodes is the substore for device_code records. The
	// handler writes a freshly minted record on every successful
	// POST.
	DeviceCodes store.DeviceCodeStore

	// Scopes is the read-only scope registry. A nil value disables
	// only the per-scope AllowedClients allowlist check; the client
	// Scopes intersection still runs.
	Scopes *scoperegistry.Registry

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

	// DPoP, when non-nil, makes /device_authorization accept and
	// verify a "DPoP" header on the inbound POST. The verifier's
	// thumbprint is bound onto the persisted record so the
	// eventual /token request must present a proof signed with
	// the same key.
	DPoP *dpop.Verifier

	// DPoPNonces is the RFC 9449 §8 nonce issuer consulted on
	// the `use_dpop_nonce` challenge response.
	DPoPNonces dpop.NonceIssuer

	// MTLS, when non-nil, makes /device_authorization stamp the
	// SHA-256 thumbprint of the inbound mTLS leaf certificate
	// onto the persisted record so the eventual /token request
	// is bound to the same certificate per RFC 8705.
	MTLS *mtls.Verifier

	// RequireSenderConstraint, when true, makes the handler
	// reject any request that arrives without DPoP and without
	// mTLS. The flag is set by the FAPI 2.0 baseline profile so
	// a deployment locked to sender-constrained tokens cannot
	// silently downgrade through device flow.
	RequireSenderConstraint bool

	// AccessTokenTTL is the lifetime advertised to the device as
	// expires_in. Zero or negative falls back to
	// [devicecode.DefaultExpiresIn].
	AccessTokenTTL time.Duration

	// PollInterval is the value advertised to the device as
	// `interval`. Zero or negative falls back to
	// [devicecode.DefaultInterval].
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

// expiresIn returns the device_code lifetime resolved against the
// default.
func (d *Deps) expiresIn() time.Duration {
	if d.AccessTokenTTL <= 0 {
		return devicecode.DefaultExpiresIn
	}
	return d.AccessTokenTTL
}

// pollInterval returns the advertised poll interval resolved
// against the default.
func (d *Deps) pollInterval() time.Duration {
	if d.PollInterval <= 0 {
		return devicecode.DefaultInterval
	}
	return d.PollInterval
}

// verificationURI returns the base verification URI advertised to
// the device, falling back to `<issuer>/device` when [Deps] does
// not override.
func (d *Deps) verificationURI() string {
	if d.VerificationURI != "" {
		return d.VerificationURI
	}
	return strings.TrimRight(d.Issuer, "/") + "/device"
}

// successResponse is the §3.2 device-authorization response body.
// All fields except verification_uri_complete are required by the
// RFC; the OP always emits verification_uri_complete so devices
// with QR-code support can render the URI without round-tripping
// the user_code.
type successResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int64  `json:"expires_in"`
	Interval                int64  `json:"interval"`
}

// Handler returns the HTTP handler the OP mounts at its
// /device_authorization endpoint. The returned handler is safe for
// concurrent use; deps MUST NOT be mutated after the call.
//
// The verification page (the embedder-owned HTML form the user
// submits the user_code through) is NOT mounted here — it lives in
// the embedder's HTTP layer per the [op/interaction] driver
// posture. The
// [github.com/libraz/go-oidc-provider/op/devicecodekit] sub-package
// ships the brute-force-protected user_code lookup
// ([devicecodekit.VerifyUserCode]) and the audit-emitting revoke
// wrapper ([devicecodekit.Revoke]) every embedder verification page
// SHOULD compose with so the per-record strike ceiling and the
// cascade-revoke audit signal stay aligned with the library's
// other surfaces.
func Handler(deps Deps) http.Handler {
	resolved := resolveDeps(deps)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Defence in depth: op.New's validateDeviceCodeGrant
		// rejects this configuration before the router mounts;
		// the wrapper short-circuits to 500 server_error when
		// an embedder bypassed op.New and forgot to wire the
		// substore. Keeping the check ahead of the method gate
		// means a misconfigured handler surfaces the
		// configuration error on every probe rather than
		// passing GET/HEAD through to the 405 path first.
		if resolved.DeviceCodes == nil {
			stampNoStore(w)
			writeError(w, http.StatusInternalServerError, errServerError,
				"device-authorization substore is not configured")
			return
		}
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
// request shape, authenticates the client, parses the requested
// parameters, mints the credential pair, and persists the
// resulting record.
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
	if name, ok := httpx.FirstDuplicateParameter(r.PostForm, deviceAuthSingleValuedParams); !ok {
		writeError(w, http.StatusBadRequest, errInvalidRequest,
			"parameter "+name+" must not be repeated")
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
	scope, ok := parseScope(w, r.PostForm, client, deps.Scopes)
	if !ok {
		return
	}
	resource, ok := parseResource(w, r.PostForm, client)
	if !ok {
		return
	}
	persist(r.Context(), w, deps, persistInput{
		Client:         client,
		Scope:          scope,
		Resource:       resource,
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
// [clientauthhttp.Authenticator] so the device-authorization
// endpoint shares an identical authentication contract with the
// token and PAR endpoints.
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
		AuditMessage:      "client authentication failed at device-authorization endpoint",
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

// enforceSenderConstraint applies the FAPI 2.0 baseline rule that
// no device-authorization request MAY produce a bearer token. When
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
		Name:     devicecode.AuditAuthorizationUnboundRejected,
		Level:    audit.LevelWarn,
		Message:  "device-authorization rejected: unbound request under sender-constraint profile",
		ClientID: clientID,
		Extras: map[string]any{
			"profile": "fapi2_baseline",
			"reason":  "unbound_request",
		},
	})
	writeError(w, http.StatusBadRequest, errInvalidRequest,
		"device authorization requires DPoP or mTLS under the active profile")
	return false
}

// verifyClientGrantTypeAllowed rejects clients whose registered
// GrantTypes do not include the device_code URN. The check matches
// the token-endpoint poll's gate so a misconfigured client cannot
// even initiate a device flow.
func verifyClientGrantTypeAllowed(ctx context.Context, w http.ResponseWriter, deps Deps, client *store.Client) bool {
	if slices.Contains(client.GrantTypes, grant.DeviceCode.String()) {
		return true
	}
	deps.auditEmitter().Emit(ctx, audit.Event{
		Name:     devicecode.AuditAuthorizationRejected,
		Level:    audit.LevelWarn,
		Message:  "device-authorization rejected: client not registered for grant",
		ClientID: client.ID,
		Extras: map[string]any{
			"reason": "grant_type_not_permitted",
		},
	})
	writeError(w, http.StatusBadRequest, errUnauthorizedClient,
		"client is not authorized for the device_code grant")
	return false
}

// parseScope extracts the requested scope from the form, validates
// it against the client's registered Scopes, and returns the
// allow-listed subset. An empty request scope falls back to the
// client's full registered set.
func parseScope(w http.ResponseWriter, form url.Values, client *store.Client, scopes *scoperegistry.Registry) ([]string, bool) {
	raw := strings.TrimSpace(form.Get("scope"))
	if raw == "" {
		return filterScopeAllowedClients(w, slices.Clone(client.Scopes), client.ID, scopes)
	}
	requested := strings.Fields(raw)
	allowed := make(map[string]struct{}, len(client.Scopes))
	for _, s := range client.Scopes {
		allowed[s] = struct{}{}
	}
	for _, s := range requested {
		if _, ok := allowed[s]; !ok {
			writeError(w, http.StatusBadRequest, errInvalidScope,
				"requested scope is not permitted for this client")
			return nil, false
		}
	}
	return filterScopeAllowedClients(w, slices.Clone(requested), client.ID, scopes)
}

func filterScopeAllowedClients(w http.ResponseWriter, scope []string, clientID string, scopes *scoperegistry.Registry) ([]string, bool) {
	for _, s := range scope {
		if !scopes.Allows(s, clientID) {
			writeError(w, http.StatusBadRequest, errInvalidScope,
				"scope is restricted to a different client")
			return nil, false
		}
	}
	return scope, true
}

// parseResource extracts the RFC 8707 resource indicators from the
// form. The function delegates parsing / validation / canonicalisation
// to [resourceindicator.Canonicalize] so the device endpoint shares the
// same policy as authorize / token / CIBA. Each surviving value MUST
// appear in the client's registered Resources allowlist; the allowlist
// match also goes through the shared helper
// ([resourceindicator.Contains]) so historical registrations that
// pre-date canonicalisation still match a canonical request. The
// current issuance pipeline honours a single audience entry, so a
// request carrying more than one non-empty resource is rejected with
// invalid_target — the handler refuses to accept input the issuance
// side would silently truncate.
func parseResource(w http.ResponseWriter, form url.Values, client *store.Client) ([]string, bool) {
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
		canonical, err := resourceindicator.Canonicalize(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, errInvalidTarget,
				"resource parameter is not a valid absolute URI")
			return nil, false
		}
		if !resourceindicator.Contains(client.Resources, canonical) {
			writeError(w, http.StatusBadRequest, errInvalidTarget,
				"resource is not registered for this client")
			return nil, false
		}
		out = append(out, canonical)
	}
	if len(out) > 1 {
		writeError(w, http.StatusBadRequest, errInvalidTarget,
			"multiple resource indicators are not supported on the device-authorization endpoint")
		return nil, false
	}
	return out, true
}

// persistInput bundles the parameters [persist] consumes. The
// struct exists to keep [serve]'s call site readable under the
// project's gocognit cap.
type persistInput struct {
	Client         *store.Client
	Scope          []string
	Resource       []string
	DPoPJKT        string
	MTLSThumbprint string
}

// persist mints the credential pair, writes the record, and
// returns the §3.2 success envelope. Save collisions on the
// device_code are treated as fatal randomness faults; user_code
// collisions trigger a bounded retry loop.
func persist(ctx context.Context, w http.ResponseWriter, deps Deps, in persistInput) {
	deviceCode, err := newDeviceCode()
	if err != nil {
		writeError(w, http.StatusInternalServerError, errServerError, "could not allocate device_code")
		return
	}
	now := deps.now().UTC()
	expiresAt := now.Add(deps.expiresIn())
	interval := deps.pollInterval()
	rec := &store.DeviceCode{
		ID:           deviceCode,
		ClientID:     in.Client.ID,
		Scope:        in.Scope,
		Resource:     in.Resource,
		DPoPJKT:      in.DPoPJKT,
		MTLSCertS256: in.MTLSThumbprint,
		Interval:     interval,
		IssuedAt:     now,
		ExpiresAt:    expiresAt,
		Status:       store.DeviceCodeStatusPending,
	}
	userCode, err := saveWithUserCodeRetry(ctx, deps.DeviceCodes, rec)
	if err != nil {
		writeError(w, http.StatusInternalServerError, errServerError, "could not persist device-code record")
		return
	}
	verificationURI := deps.verificationURI()
	complete := verificationURI + "?user_code=" + url.QueryEscape(userCode)
	deps.auditEmitter().Emit(ctx, audit.Event{
		Name:     devicecode.AuditAuthorizationIssued,
		Level:    audit.LevelInfo,
		Message:  "device-authorization issued",
		ClientID: in.Client.ID,
		Extras: map[string]any{
			"scope":      in.Scope,
			"resource":   in.Resource,
			"expires_in": int64(deps.expiresIn().Seconds()),
			"interval":   int64(interval.Seconds()),
			"binding":    bindingLabel(in.DPoPJKT, in.MTLSThumbprint),
		},
	})
	stampNoStore(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(successResponse{
		DeviceCode:              deviceCode,
		UserCode:                userCode,
		VerificationURI:         verificationURI,
		VerificationURIComplete: complete,
		ExpiresIn:               int64(deps.expiresIn().Seconds()),
		Interval:                int64(interval.Seconds()),
	})
}

// saveWithUserCodeRetry generates a fresh user_code and persists
// the record. On collision (the user_code map is densely-populated
// during high-volume flows) the function retries with a fresh
// user_code up to [userCodeRetryBudget] times. The return value
// carries the user_code that was successfully persisted.
func saveWithUserCodeRetry(ctx context.Context, store store.DeviceCodeStore, rec *store.DeviceCode) (string, error) {
	for range userCodeRetryBudget {
		userCode, err := devicecode.NewUserCode()
		if err != nil {
			return "", err
		}
		rec.UserCode = userCode
		if err := store.Save(ctx, rec); err != nil {
			if errors.Is(err, errAlreadyExists()) {
				continue
			}
			return "", err
		}
		return userCode, nil
	}
	return "", errors.New("devicecodeendpoint: exhausted user_code retry budget")
}

// errAlreadyExists is a small indirection that avoids the lint
// gate against importing op/store.ErrAlreadyExists on every
// import; the store package's sentinel is the source of truth and
// the helper just routes [errors.Is] into it without expanding
// the package import surface.
func errAlreadyExists() error {
	return store.ErrAlreadyExists
}

// newDeviceCode returns a freshly generated device_code: 32 bytes
// of crypto/rand encoded as base64url-no-pad (256 bits of
// entropy). The body lives in this package rather than
// [internal/devicecode] because the wire-secret path is owned by
// the issuer side; the helper packages stay free of HTTP / I/O
// concerns.
func newDeviceCode() (string, error) {
	buf := make([]byte, deviceCodeByteLength)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("devicecodeendpoint: read random: %w", err)
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
// etc.). Mirrors the helper in [internal/parendpoint] so the two
// endpoints stay aligned.
func isFormContent(ct string) bool {
	return endpointsupport.IsFormContent(ct)
}
