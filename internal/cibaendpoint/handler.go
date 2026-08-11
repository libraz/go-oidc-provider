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
	"strconv"
	"strings"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/ciba"
	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/clientauth/clientauthhttp"
	"github.com/libraz/go-oidc-provider/internal/dpop"
	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/internal/httpx"
	"github.com/libraz/go-oidc-provider/internal/jar"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/mtls"
	"github.com/libraz/go-oidc-provider/internal/resourceindicator"
	"github.com/libraz/go-oidc-provider/internal/scoperegistry"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/store"
)

// fapiCIBAMaxRequestedExpiry caps the auth_req_id lifetime a client may
// request under the FAPI-CIBA profile. FAPI-CIBA-ID1 §5 inherits the
// FAPI 2.0 §3.1.9 ten-minute access-token lifetime cap and applies it
// to the backchannel-authentication TTL: any requested_expiry above
// 600s MUST be rejected (not silently clamped) so the wire response
// reflects the operator-mandated ceiling.
const fapiCIBAMaxRequestedExpiry = 10 * time.Minute

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
// classifying the hint kind.
//
// What value arrives depends on the kind:
//
//   - [ciba.HintLoginHint] and [ciba.HintLoginHintToken] deliver the
//     raw wire parameter. The OP has no way to interpret either, so
//     verifying a login_hint_token's signature and issuer is the
//     implementation's job.
//   - [ciba.HintIDTokenHint] delivers the OP-verified sub claim, NOT
//     the JWT. The handler has already checked the signature against
//     the OP keyset, the iss claim, and that the audience identifies
//     the authenticated client (CIBA Core 1.0 §7.1), so the value is
//     an OP-issued subject the implementation can look up directly.
//
// Implementations MUST:
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

	// Scopes is the read-only scope registry. A nil value disables
	// only the per-scope AllowedClients allowlist check; the client
	// Scopes intersection still runs.
	Scopes *scoperegistry.Registry

	// Keys is the OP signing keyset (active plus retiring entries) an
	// inbound id_token_hint is verified against per CIBA Core 1.0
	// §7.1. A nil keyset does not weaken the endpoint: it makes every
	// id_token_hint request fail with server_error, because the OP
	// cannot establish that the presented token is one it issued and
	// MUST NOT pass an unverified assertion of identity onward.
	// Requests carrying login_hint or login_hint_token are unaffected.
	Keys *keys.Set

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

	// JAR, when non-nil, makes /bc-authorize accept a "request"
	// form parameter carrying a signed authentication request
	// per FAPI-CIBA-ID1 §5.2.2. The handler verifies the JWT
	// against the authenticated client's keyset and merges the
	// claims onto the form values before parsing CIBA-specific
	// parameters. A nil verifier rejects any request that
	// carries a "request" parameter with invalid_request — CIBA
	// Core §13 does not list invalid_request_object as a BCA error
	// code, so all request-object failures collapse onto
	// invalid_request.
	JAR *jar.Verifier

	// RequireSignedAuthRequest, when true, makes the handler
	// reject any /bc-authorize POST that does not carry a
	// "request" parameter with invalid_request. The flag is set
	// by FAPI-CIBA so a profile-locked deployment cannot accept
	// unsigned form submissions. When set, [Deps.JAR] MUST be
	// non-nil — the constructor in [op] enforces that pairing
	// at startup.
	RequireSignedAuthRequest bool

	// FAPICIBAProfileActive reports whether the FAPI-CIBA profile is
	// currently selected. The flag flips the TTL gate from the vanilla
	// "clamp silently against [Deps.MaxExpiresIn]" posture to the
	// FAPI-CIBA-ID1 §5 / FAPI 2.0 §3.1.9 hard-reject posture: any
	// requested_expiry above the ten-minute cap surfaces as
	// invalid_request rather than being clamped down without notice.
	// Set by [op] when the active profile set contains
	// [profile.FAPICIBA]; non-FAPI deployments leave it false and
	// retain the legacy clamp behaviour.
	FAPICIBAProfileActive bool

	// ACRValuesSupported is the OP-side allowlist of Authentication
	// Context Class Reference values published in discovery via
	// `acr_values_supported`. Empty means the OP did not advertise the
	// list and any client-supplied acr_values value is accepted (the
	// legacy posture); a non-empty slice makes the handler validate
	// every requested value against the list per OIDC Core 1.0
	// §3.1.2.1 (acr_values handling) + CIBA Core 1.0 §7.1, rejecting
	// any unsupported entry with invalid_request so a client cannot
	// drive the OP to mint an id_token bearing an `acr` claim the
	// operator never enrolled.
	ACRValuesSupported []string

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
//
// Defence in depth: op.New's validateCIBAGrant rejects a
// configured-but-unwired substore at construction time, but a
// caller that bypasses op.New (e.g. constructs the handler
// directly) and forgets to wire CIBARequests would otherwise
// reach a nil-interface Save inside serve. The wrapper short-
// circuits to 500 server_error before any request work, keeping
// the bug visible without crashing the process.
func Handler(deps Deps) http.Handler {
	resolved := resolveDeps(deps)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if resolved.CIBARequests == nil {
			stampNoStore(w)
			writeError(w, http.StatusInternalServerError, errServerError,
				"backchannel-authentication substore is not configured")
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
// request shape, authenticates the client, classifies the hint,
// resolves it to a subject, parses the requested parameters,
// mints the auth_req_id, and persists the resulting record.
//
// The gates are enumerated in flat shape so each one maps onto the
// CIBA Core clause it enforces; folding them into helpers would
// obscure the request ordering.
func serve(w http.ResponseWriter, r *http.Request, deps Deps) {
	if !parseAndValidateForm(w, r) {
		return
	}
	dpopJKT, client, ok := authenticateWithDPoP(w, r, deps)
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
	merged, ok := consumeJARRequestObject(r.Context(), w, deps, client, r.PostForm)
	if !ok {
		return
	}
	hintKind, hintValue, ok := classifyHint(r.Context(), w, deps, merged, client.ID)
	if !ok {
		return
	}
	subject, ok := resolveHint(r.Context(), w, deps, hintKind, hintValue, client)
	if !ok {
		return
	}
	scope, ok := parseScope(r.Context(), w, deps, merged, client)
	if !ok {
		return
	}
	resource, ok := parseResource(w, merged, client)
	if !ok {
		return
	}
	acrValues, ok := parseACRValues(w, merged.Get("acr_values"), deps)
	if !ok {
		return
	}
	bindingMessage, ok := parseBindingMessage(w, merged.Get("binding_message"))
	if !ok {
		return
	}
	expiresIn, ok := parseRequestedExpiry(w, merged.Get("requested_expiry"), deps)
	if !ok {
		return
	}
	userCode, ok := parseUserCode(w, merged.Get("user_code"))
	if !ok {
		return
	}
	if !parseClientNotificationToken(w, merged.Get("client_notification_token")) {
		return
	}
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

// parseAndValidateForm runs the request-shape gates that must clear
// before any cryptographic or business work: HTTP method, content
// type, body size, body parse, and the RFC 6749 §3.2 single-valued
// duplicate-parameter rejection (CIBA Core §7.1 inherits §3.2). On
// any failure the function writes the wire envelope and returns
// false. On success r.PostForm is populated and the caller proceeds.
func parseAndValidateForm(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		stampNoStore(w)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	if !isFormContent(r.Header.Get("Content-Type")) {
		writeError(w, http.StatusBadRequest, errInvalidRequest,
			"content-type must be application/x-www-form-urlencoded")
		return false
	}
	endpointsupport.LimitFormBody(w, r)
	if err := r.ParseForm(); err != nil { //nolint:gosec // body bounded by LimitFormBody above
		writeError(w, http.StatusBadRequest, errInvalidRequest, "malformed form body")
		return false
	}
	if name, ok := firstDuplicateParameter(r.PostForm); !ok {
		writeError(w, http.StatusBadRequest, errInvalidRequest,
			"parameter "+name+" must not be repeated")
		return false
	}
	return true
}

// authenticateWithDPoP runs DPoP proof verification and client
// authentication in the one order that satisfies both of the
// constraints the two mechanisms impose, and returns the proof's RFC
// 7638 thumbprint ("" when no proof was presented) alongside the
// authenticated client.
//
// Proof verification runs FIRST so the RFC 9449 §8 `use_dpop_nonce`
// challenge fires before any client_assertion jti is consumed: §8
// contemplates a verbatim retry of the client-side request body with
// only the proof refreshed, and RP libraries rebuild only the DPoP
// header, reusing the original client_assertion. Marking the
// assertion's jti on the first attempt would surface on the retry as
// invalid_client. Nothing in the verification depends on the resolved
// client identity — the proof is bound to the request and to its own
// key, never to the client's credential.
//
// The proof's replay marker is written LAST, after authentication
// succeeds. /bc-authorize requires a credential, so that write is the
// one place where an unauthenticated request rate would translate into
// storage cost, and a proof burned on a request that never
// authenticated would make the legitimate retry look like a replay.
// The token and PAR endpoints apply the identical ordering.
//
// The function writes the response on every failure path; the caller
// only checks the bool.
func authenticateWithDPoP(w http.ResponseWriter, r *http.Request, deps Deps) (string, *store.Client, bool) {
	checked, ok := verifyDPoPProof(r, w, deps)
	if !ok {
		return "", nil, false
	}
	client, _, ok := authenticate(r.Context(), w, r, deps)
	if !ok {
		return "", nil, false
	}
	if !commitDPoPProof(r.Context(), w, deps, checked) {
		return "", nil, false
	}
	return checkedJKT(checked), client, true
}

// verifyDPoPProof runs the stateless RFC 9449 §4.3 gates over the
// optional DPoP header and returns the accepted proof when one was
// presented. When [Deps.DPoP] is nil or the request does not carry a
// proof, the returned proof is nil and the handler proceeds. When the
// proof is present and verification fails, the function writes the
// RFC 9449 §8 envelope and returns ok=false.
//
// The proof is not single-use until [commitDPoPProof] has run; see
// [authenticateWithDPoP] for why the two phases are kept apart.
func verifyDPoPProof(r *http.Request, w http.ResponseWriter, deps Deps) (*dpop.Checked, bool) {
	if deps.DPoP == nil {
		return nil, true
	}
	if r.Header.Get("DPoP") == "" {
		return nil, true
	}
	checked, err := deps.DPoP.CheckHTTPRequest(r.Context(), r, "")
	if err != nil {
		writeDPoPError(r.Context(), w, deps, err)
		return nil, false
	}
	return checked, true
}

// commitDPoPProof writes the replay marker for the proof
// [verifyDPoPProof] accepted, making it single-use. It is a no-op when
// no proof was presented. The function emits the response and returns
// false on failure; a repeated or concurrent use of the same proof
// surfaces through the same [dpop.WriteError] mapping the single-phase
// verifier produced.
func commitDPoPProof(ctx context.Context, w http.ResponseWriter, deps Deps, checked *dpop.Checked) bool {
	if checked == nil {
		return true
	}
	if err := deps.DPoP.Commit(ctx, checked); err != nil {
		writeDPoPError(ctx, w, deps, err)
		return false
	}
	return true
}

// checkedJKT returns the proof's RFC 7638 thumbprint, or "" when no
// proof was presented. The helper keeps the nil handling out of
// [authenticateWithDPoP]'s return statement.
func checkedJKT(checked *dpop.Checked) string {
	if checked == nil {
		return ""
	}
	return checked.JKT
}

// writeDPoPError translates a dpop.Err* sentinel onto the wire form,
// including the RFC 9449 §8 `use_dpop_nonce` challenge. Both proof
// phases route through it so their boundary mapping cannot drift.
func writeDPoPError(ctx context.Context, w http.ResponseWriter, deps Deps, err error) {
	dpop.WriteError(ctx, w, err, dpop.NonceSourceFromIssuer(deps.DPoPNonces))
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

// consumeJARRequestObject inspects the form values for a "request"
// parameter. When present, it verifies the JWT against the
// authenticated client and merges the claims onto the form values
// per RFC 9101 §6.1 / FAPI-CIBA-ID1 §5.2.2. A nil [Deps.JAR] means
// the OP has not enabled JAR; the request is rejected with
// invalid_request (CIBA Core §13 does not list
// invalid_request_object as a BCA error code).
//
// When [Deps.RequireSignedAuthRequest] is true and "request" is
// missing, the request is rejected with invalid_request because
// FAPI-CIBA-ID1 §5.2.2 mandates a signed authentication request on
// every /bc-authorize POST.
//
// The returned bool is false when the function wrote the response;
// the caller then stops processing.
func consumeJARRequestObject(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	client *store.Client,
	values url.Values,
) (url.Values, bool) {
	raw := values.Get("request")
	if raw == "" {
		if deps.RequireSignedAuthRequest {
			deps.auditEmitter().Emit(ctx, audit.Event{
				Name:     ciba.AuditAuthorizationRejected,
				Level:    audit.LevelWarn,
				Message:  "backchannel-authentication rejected: signed request object required",
				ClientID: client.ID,
				Extras: map[string]any{
					"reason": "request_object_required",
				},
			})
			writeError(w, http.StatusBadRequest, errInvalidRequest,
				"request object is required by the active profile")
			return nil, false
		}
		return values, true
	}
	if deps.JAR == nil {
		deps.auditEmitter().Emit(ctx, audit.Event{
			Name:     ciba.AuditAuthorizationRejected,
			Level:    audit.LevelWarn,
			Message:  "backchannel-authentication rejected: request object not supported",
			ClientID: client.ID,
			Extras: map[string]any{
				"reason": "request_object_invalid",
			},
		})
		writeError(w, http.StatusBadRequest, errInvalidRequest,
			"request is not supported by this OP")
		return nil, false
	}
	obj, err := deps.JAR.VerifyCIBA(ctx, raw, client.ID, client)
	if err != nil {
		deps.auditEmitter().Emit(ctx, audit.Event{
			Name:     ciba.AuditAuthorizationRejected,
			Level:    audit.LevelWarn,
			Message:  "backchannel-authentication rejected: request object verification failed",
			ClientID: client.ID,
			Extras: map[string]any{
				"reason": "request_object_invalid",
			},
		})
		writeJARError(w, err)
		return nil, false
	}
	merged, err := jar.Merge(values, obj)
	if err != nil {
		deps.auditEmitter().Emit(ctx, audit.Event{
			Name:     ciba.AuditAuthorizationRejected,
			Level:    audit.LevelWarn,
			Message:  "backchannel-authentication rejected: request object merge failed",
			ClientID: client.ID,
			Extras: map[string]any{
				"reason": "request_object_invalid",
			},
		})
		writeJARError(w, err)
		return nil, false
	}
	return merged, true
}

// writeJARError translates a [jar] sentinel into the CIBA wire
// envelope. CIBA Core §13 enumerates a closed set of BCA error
// codes that does NOT include "invalid_request_object" (unlike the
// /authorize endpoint, which does). Every JAR failure therefore
// surfaces as "invalid_request" so OFCS' CIBA-13 negative tests see
// the spec-mandated code; the human-readable description carries
// the precise sentinel detail.
func writeJARError(w http.ResponseWriter, err error) {
	writeError(w, http.StatusBadRequest, errInvalidRequest,
		jarDescriptionFor(err))
}

// jarDescriptions is the sentinel-to-string catalogue
// [jarDescriptionFor] walks. Mirrors the parendpoint table —
// duplicated rather than shared because the cibaendpoint package
// does not import parendpoint.
//
//nolint:gochecknoglobals // immutable error-to-description catalogue.
var jarDescriptions = []struct {
	sentinel error
	desc     string
}{
	{jar.ErrAlgNotAllowed, "request object alg is not allowed"},
	{jar.ErrSigInvalid, "request object signature is invalid"},
	{jar.ErrIssMismatch, "request object iss does not match client_id"},
	{jar.ErrAudMismatch, "request object aud does not match issuer"},
	{jar.ErrExpired, "request object is expired or too old"},
	{jar.ErrNotYetValid, "request object is not yet valid"},
	{jar.ErrNestedRequest, "request object must not contain nested request parameters"},
	{jar.ErrJWKSFetch, "client jwks fetch failed"},
	{jar.ErrNoMatchingJWK, "no matching client jwk"},
	{jar.ErrJWKSConfigured, "client has no JWKs or JWKsURI"},
	{jar.ErrJTIMissing, "request object missing jti"},
	{jar.ErrJTIReplayed, "request object jti already consumed"},
	{jar.ErrIATMissing, "request object missing iat"},
	{jar.ErrEncryptionUnsupported, "encrypted request objects are not supported"},
	{jar.ErrEncryptionAlgNotAllowed, "request object encryption alg/enc is not allowed"},
	{jar.ErrDecryptFailed, "request object could not be decrypted"},
	{jar.ErrParse, "request object is malformed"},
}

// jarDescriptionFor returns a short description for a JAR sentinel.
func jarDescriptionFor(err error) string {
	for _, entry := range jarDescriptions {
		if errors.Is(err, entry.sentinel) {
			return entry.desc
		}
	}
	return "request object verification failed"
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

// pairwiseSubjectType is the OIDC Core 1.0 §8 subject_type value that
// makes a client's "sub" a per-sector pseudonym rather than the
// OP-internal identifier. Mirrors the literal the issuance-side
// subject projector dispatches on.
const pairwiseSubjectType = "pairwise"

// verifyIDTokenHint runs the CIBA Core 1.0 §7.1 verification the OP
// owes an inbound id_token_hint and returns the value the resolver
// should see. For every other hint kind the raw parameter passes
// through untouched.
//
// On the id_token_hint branch the returned value is the OP-verified
// sub claim, not the JWT: the token's signature is checked against the
// OP keyset, its iss must be this issuer, and its audience must
// identify the client that authenticated on this very request. Without
// that last binding any CIBA-registered client could present an ID
// Token minted for a different client and have the ceremony addressed
// to a subject it was never entitled to name.
//
// Pairwise clients are refused outright. A client registered with
// subject_type=pairwise receives per-sector pseudonyms (OIDC Core 1.0
// §8.1), which are SHA-256 outputs the OP keeps no reverse index for;
// the one place the library recovers a raw subject from a projected
// one pivots through an access token's grant lineage, and an ID Token
// carries no such lineage. Handing the resolver a pseudonym it cannot
// map would either fail confusingly or invite the embedder to guess,
// so the request is rejected with a description that names the
// supported alternative.
//
// The bool is false when the function wrote the response.
func verifyIDTokenHint(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	kind ciba.HintKind,
	value string,
	client *store.Client,
) (string, bool) {
	if kind != ciba.HintIDTokenHint {
		return value, true
	}
	if client.SubjectType == pairwiseSubjectType {
		emitHintRejected(ctx, deps, client.ID, "id_token_hint_pairwise_unsupported")
		writeError(w, http.StatusBadRequest, errInvalidRequest,
			"id_token_hint is not accepted from a client using pairwise subject identifiers; "+
				"use login_hint or login_hint_token")
		return "", false
	}
	subject, err := ciba.VerifyIDTokenHint(ctx, deps.Keys, deps.Issuer, client.ID, value)
	if err != nil {
		if errors.Is(err, ciba.ErrIDTokenHintUnverifiable) {
			emitHintRejected(ctx, deps, client.ID, "id_token_hint_unverifiable")
			writeError(w, http.StatusInternalServerError, errServerError,
				"id_token_hint verification is not configured")
			return "", false
		}
		// Every client-facing cause collapses onto one code and one
		// description so the wire surface cannot be probed to learn
		// which check rejected the token.
		emitHintRejected(ctx, deps, client.ID, "id_token_hint_invalid")
		writeError(w, http.StatusBadRequest, errInvalidRequest,
			"id_token_hint is not an id_token this OP issued to this client")
		return "", false
	}
	return subject, true
}

// emitHintRejected records a hint-verification rejection on the audit
// stream. reason is a stable code string; the wire response carries
// less detail on purpose, so the audit event is where an operator
// learns which gate closed.
func emitHintRejected(ctx context.Context, deps Deps, clientID, reason string) {
	deps.auditEmitter().Emit(ctx, audit.Event{
		Name:     ciba.AuditAuthorizationRejected,
		Level:    audit.LevelWarn,
		Message:  "backchannel-authentication rejected: id_token_hint not accepted",
		ClientID: clientID,
		Extras: map[string]any{
			"reason": reason,
		},
	})
}

// resolveHint runs the OP-side id_token_hint verification and then
// invokes the embedder's [HintResolver], mapping the outcome onto the
// wire response. A nil resolver collapses onto login_required so a
// misconfigured deployment never silently resolves every hint to the
// empty subject.
//
// The verification runs here rather than at the call site so no future
// edit can reorder the two: on the [ciba.HintIDTokenHint] branch the
// resolver receives the OP-verified sub produced by
// [verifyIDTokenHint], never the JWT.
func resolveHint(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	kind ciba.HintKind,
	value string,
	client *store.Client,
) (string, bool) {
	clientID := client.ID
	value, ok := verifyIDTokenHint(ctx, w, deps, kind, value, client)
	if !ok {
		return "", false
	}
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
		if !deps.Scopes.Allows(s, client.ID) {
			writeError(w, http.StatusBadRequest, errInvalidScope,
				"scope is restricted to a different client")
			return nil, false
		}
	}
	return slices.Clone(scope), true
}

// parseResource extracts the RFC 8707 resource indicators from the
// form. The function delegates parsing / validation / canonicalisation
// to [resourceindicator.Canonicalize] so the backchannel-authentication
// endpoint shares the same policy as authorize / token / device. Each
// surviving value MUST appear in the client's registered Resources
// allowlist; the allowlist match also goes through the shared helper
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
			"multiple resource indicators are not supported on the backchannel-authentication endpoint")
		return nil, false
	}
	return out, true
}

// parseACRValues splits the acr_values parameter on ASCII whitespace
// and validates every entry against the OP-advertised list. OIDC Core
// 1.0 §3.1.2.1 (acr_values handling) + CIBA Core 1.0 §7.1 require the
// OP to refuse client-requested ACR values it has not enrolled to
// recognise: silently accepting the request would let a client drive
// the issued id_token's `acr` claim to any string regardless of what
// the OP actually supports.
//
// The validation runs only when [Deps.ACRValuesSupported] is non-empty
// (the operator declared the allowlist in discovery); an empty list
// preserves the legacy "carry verbatim" posture so a deployment that
// did not opt into discovery advertisement is unaffected.
func parseACRValues(w http.ResponseWriter, raw string, deps Deps) ([]string, bool) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, true
	}
	values := strings.Fields(trimmed)
	if len(deps.ACRValuesSupported) == 0 {
		return values, true
	}
	for _, v := range values {
		if !slices.Contains(deps.ACRValuesSupported, v) {
			writeError(w, http.StatusBadRequest, errInvalidRequest,
				"acr_values entry "+v+" is not advertised in acr_values_supported")
			return nil, false
		}
	}
	return values, true
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

// parseRequestedExpiry dispatches to [ciba.ParseRequestedExpiry] and
// maps the sentinel onto the wire response. A zero return value means
// the client did not supply requested_expiry; the caller substitutes
// [Deps.effectiveExpiresIn].
//
// Under FAPI-CIBA the helper additionally enforces the FAPI-CIBA-ID1
// §5 / FAPI 2.0 §3.1.9 ten-minute lifetime cap as a hard reject:
// requested_expiry above [fapiCIBAMaxRequestedExpiry] surfaces as
// invalid_request rather than being clamped silently. The
// non-FAPI-CIBA path keeps the legacy clamp posture so vanilla
// deployments still tolerate over-spec asks against
// [Deps.MaxExpiresIn].
func parseRequestedExpiry(
	w http.ResponseWriter,
	raw string,
	deps Deps,
) (time.Duration, bool) {
	if deps.FAPICIBAProfileActive {
		trimmed := strings.TrimSpace(raw)
		if trimmed != "" {
			n, err := strconv.ParseInt(trimmed, 10, 64)
			if err == nil && n > int64(fapiCIBAMaxRequestedExpiry.Seconds()) {
				writeError(w, http.StatusBadRequest, errInvalidRequest,
					"requested_expiry exceeds FAPI-CIBA 10-minute cap")
				return 0, false
			}
		}
	}
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

// parseUserCode validates the user_code form parameter. The library
// does not advertise `backchannel_user_code_parameter_supported=true`
// in discovery (the option to flip the flag is reserved for a future
// release), and CIBA Core 1.0 §7.1 requires a client to refrain from
// sending parameters the OP has not advertised. The handler therefore
// rejects any non-empty user_code with invalid_request rather than
// silently stamping it onto the persisted record where it would have
// no downstream effect.
func parseUserCode(w http.ResponseWriter, raw string) (string, bool) {
	if strings.TrimSpace(raw) == "" {
		return "", true
	}
	writeError(w, http.StatusBadRequest, errInvalidRequest,
		"user_code parameter is not supported")
	return "", false
}

func parseClientNotificationToken(w http.ResponseWriter, raw string) bool {
	if strings.TrimSpace(raw) == "" {
		return true
	}
	writeError(w, http.StatusBadRequest, errInvalidRequest,
		"client_notification_token parameter is not supported")
	return false
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
// internal/ciba because the wire-secret path is owned by the
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

// cibaSingleValuedParams is the closed list of /bc-authorize form
// parameters RFC 6749 §3.2 forbids from appearing more than once.
// "resource" is intentionally absent — RFC 8707 §2 allows the
// resource indicator to repeat — and any unknown form key is
// silently tolerated (the catalog row CIBA-024 / CIBA-025 documents
// the "ignore unknown form params" posture).
//
//nolint:gochecknoglobals // closed allow-list, intentional package state.
var cibaSingleValuedParams = []string{
	"scope",
	"login_hint",
	"login_hint_token",
	"id_token_hint",
	"binding_message",
	"user_code",
	"acr_values",
	"requested_expiry",
	"request",
	"client_notification_token",
}

// firstDuplicateParameter wraps [httpx.FirstDuplicateParameter] with
// the CIBA-specific [cibaSingleValuedParams] list. The helper is
// retained as a thin local alias so the call site reads at the same
// abstraction level as the rest of /bc-authorize.
func firstDuplicateParameter(values url.Values) (string, bool) {
	return httpx.FirstDuplicateParameter(values, cibaSingleValuedParams)
}

// isFormContent reports whether ct is application/x-www-form-
// urlencoded, tolerating optional parameters (charset, boundary,
// etc.).
func isFormContent(ct string) bool {
	return endpointsupport.IsFormContent(ct)
}
