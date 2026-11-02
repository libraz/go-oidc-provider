package devicecodeendpoint

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/devicecode"
	"github.com/libraz/go-oidc-provider/internal/dpop"
	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/internal/httpx"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/mtls"
	"github.com/libraz/go-oidc-provider/internal/oidcscope"
	"github.com/libraz/go-oidc-provider/internal/scoperegistry"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/store"
)

// Tunables the handler uses when [Deps] omits the corresponding
// field. The defaults match the values.
const (
	// deviceCodeByteLength is the entropy of the wire device_code.
	// 32 bytes (256 bits) is the same posture the library uses for
	// authorization codes and refresh tokens, well above the §3.2
	// "guessing infeasible" requirement.
	deviceCodeByteLength = 32

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

// Clock is the package-local name for the shared wall-clock interface; a nil
// Clock falls back to the system clock.
type Clock = timex.Clock

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
	// falls back to [timex.SystemClock].
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

	// DeviceCodeTTL is the device_code lifetime advertised to the
	// device as expires_in (RFC 8628 §3.2). This is deliberately
	// independent of the OP's access-token TTL: a deployment running
	// a short access-token lifetime must still give a distracted
	// user enough time to reach a secondary device and complete the
	// verification ceremony. Zero or negative falls back to
	// [devicecode.DefaultExpiresIn].
	DeviceCodeTTL time.Duration

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
	return audit.OrDiscard(d.Audit)
}

// now returns the wall-clock reading for this request, falling
// back to the system clock when [Deps.Clock] is nil.
func (d *Deps) now() time.Time {
	return timex.OrSystem(d.Clock).Now()
}

// expiresIn returns the device_code lifetime resolved against the
// default.
func (d *Deps) expiresIn() time.Duration {
	if d.DeviceCodeTTL <= 0 {
		return devicecode.DefaultExpiresIn
	}
	return d.DeviceCodeTTL
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
// RFC; the OP emits verification_uri_complete whenever it can build
// one so devices with QR-code support can render the URI without
// round-tripping the user_code, and omits the member outright rather
// than advertising a link it could not assemble.
type successResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
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
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Defence in depth: op.New's validateDeviceCodeGrant
		// rejects this configuration before the router mounts;
		// the wrapper short-circuits to 500 server_error when
		// an embedder bypassed op.New and forgot to wire the
		// substore. Keeping the check ahead of the method gate
		// means a misconfigured handler surfaces the
		// configuration error on every probe rather than
		// passing GET/HEAD through to the 405 path first.
		if deps.DeviceCodes == nil {
			httpx.StampNoStore(w)
			endpointsupport.WriteOAuthError(w, http.StatusInternalServerError, errServerError,
				"device-authorization substore is not configured")
			return
		}
		serve(w, r, deps)
	})
}

// serve is the request-scoped entry point. It validates the
// request shape, authenticates the client, parses the requested
// parameters, mints the credential pair, and persists the
// resulting record.
func serve(w http.ResponseWriter, r *http.Request, deps Deps) {
	if !endpointsupport.ParseFormRequest(w, r, deviceAuthSingleValuedParams) {
		return
	}
	gate := deps.initiationGate()
	dpopJKT, client, ok := gate.Authenticate(w, r)
	if !ok {
		return
	}
	mtlsThumbprint, ok := endpointsupport.ExtractMTLSThumbprint(w, r, deps.MTLS)
	if !ok {
		return
	}
	if !gate.EnforceSenderConstraint(r.Context(), w, dpopJKT, mtlsThumbprint, client.ID) {
		return
	}
	if !gate.VerifyClientGrantType(r.Context(), w, client) {
		return
	}
	scope, ok := parseScope(w, r.PostForm, client, deps.Scopes)
	if !ok {
		return
	}
	resource, ok := endpointsupport.ParseSingleResource(w, r.PostForm, client, "device-authorization endpoint")
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

// initiationGate builds the client-authentication, sender-constraint
// (FAPI 2.0 baseline) and grant-registration gates for the
// device-authorization endpoint.
func (d *Deps) initiationGate() endpointsupport.InitiationGate {
	return endpointsupport.InitiationGate{
		DPoP: dpop.Gate{Verifier: d.DPoP, Nonces: d.DPoPNonces},
		Auth: endpointsupport.AuthenticateOpts{
			Clients:           d.Clients,
			SecretVerifier:    d.SecretVerifier,
			AssertionVerifier: d.AssertionVerifier,
			AllowedMethods:    d.AllowedClientAuthMethods,
			Now:               d.now(),
			Audit:             d.auditEmitter(),
		},
		AuthFailureMessage:      "client authentication failed at device-authorization endpoint",
		RequireSenderConstraint: d.RequireSenderConstraint,
		Unbound: endpointsupport.SenderConstraintRejection{
			Event:        devicecode.AuditAuthorizationUnboundRejected,
			AuditMessage: "device-authorization rejected: unbound request under sender-constraint profile",
			Description:  "device authorization requires DPoP or mTLS under the active profile",
		},
		GrantURN: grant.DeviceCode.String(),
		GrantMissing: endpointsupport.GrantRejection{
			Event:        devicecode.AuditAuthorizationRejected,
			AuditMessage: "device-authorization rejected: client not registered for grant",
			Description:  "client is not authorized for the device_code grant",
		},
	}
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
	// strings.Fields (any Unicode whitespace) is a deliberate superset of
	// the RFC 6749 §3.3 0x20 separator; spec-conformant inputs tokenise
	// identically to the wire-facing 0x20-only internal/oidcscope path.
	requested := strings.Fields(raw)
	if !oidcscope.Subset(requested, client.Scopes) {
		endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errInvalidScope,
			"requested scope is not permitted for this client")
		return nil, false
	}
	return filterScopeAllowedClients(w, slices.Clone(requested), client.ID, scopes)
}

func filterScopeAllowedClients(w http.ResponseWriter, scope []string, clientID string, scopes *scoperegistry.Registry) ([]string, bool) {
	if !scopes.AllowsAll(scope, clientID) {
		endpointsupport.WriteOAuthError(w, http.StatusBadRequest, errInvalidScope,
			"scope is restricted to a different client")
		return nil, false
	}
	return scope, true
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
	deviceCode, err := keys.RandomBase64URL(deviceCodeByteLength)
	if err != nil {
		endpointsupport.WriteOAuthError(w, http.StatusInternalServerError, errServerError, "could not allocate device_code")
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
		endpointsupport.WriteOAuthError(w, http.StatusInternalServerError, errServerError, "could not persist device-code record")
		return
	}
	verificationURI := deps.verificationURI()
	complete := completeVerificationURI(verificationURI, userCode)
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
			"binding":    endpointsupport.BindingLabel(in.DPoPJKT, in.MTLSThumbprint),
		},
	})
	httpx.StampNoStore(w)
	_ = httpx.WriteJSON(w, http.StatusOK, successResponse{
		DeviceCode:              deviceCode,
		UserCode:                userCode,
		VerificationURI:         verificationURI,
		VerificationURIComplete: complete,
		ExpiresIn:               int64(deps.expiresIn().Seconds()),
		Interval:                int64(interval.Seconds()),
	})
}

// completeVerificationURI returns the RFC 8628 §3.3.1
// verification_uri_complete: the verification URI carrying the
// user_code as a query parameter, so a device rendering a QR code
// hands the user a link that already contains the code.
//
// The parameter is merged into the URI's existing query rather than
// appended textually. An embedder is free to point
// [Deps.VerificationURI] at a page that already carries query
// parameters (a tenant selector, say) or a fragment; concatenating
// "?user_code=" onto such a URI produces a second "?" and a link the
// user_code never survives, and nothing downstream would reject it. A
// pre-existing user_code parameter is replaced so the emitted link can
// only carry the code this record was issued with.
//
// An unparseable base yields the empty string, which drops the
// OPTIONAL member from the response rather than advertising a broken
// link; the public option that sets the base rejects unparseable input
// at construction, so this is a defensive fallback for direct
// handler embedders.
func completeVerificationURI(base, userCode string) string {
	u, err := url.Parse(base)
	if err != nil {
		return ""
	}
	q := u.Query()
	q.Set("user_code", userCode)
	u.RawQuery = q.Encode()
	return u.String()
}

// saveWithUserCodeRetry generates a fresh user_code and persists
// the record. On collision (the user_code map is densely-populated
// during high-volume flows) the function retries with a fresh
// user_code up to [userCodeRetryBudget] times. The return value
// carries the user_code that was successfully persisted.
func saveWithUserCodeRetry(ctx context.Context, codes store.DeviceCodeStore, rec *store.DeviceCode) (string, error) {
	for range userCodeRetryBudget {
		userCode, err := devicecode.NewUserCode()
		if err != nil {
			return "", err
		}
		rec.UserCode = userCode
		if err := codes.Save(ctx, rec); err != nil {
			if errors.Is(err, store.ErrAlreadyExists) {
				continue
			}
			return "", err
		}
		return userCode, nil
	}
	return "", errors.New("devicecodeendpoint: exhausted user_code retry budget")
}
