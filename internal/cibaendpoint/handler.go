package cibaendpoint

import (
	"context"
	"net/http"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/ciba"
	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/dpop"
	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/internal/httpx"
	"github.com/libraz/go-oidc-provider/internal/jar"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/mtls"
	"github.com/libraz/go-oidc-provider/internal/scoperegistry"
	"github.com/libraz/go-oidc-provider/internal/timex"
	"github.com/libraz/go-oidc-provider/op/store"
)

// Clock is the package-local name for the shared wall-clock interface; a nil
// Clock falls back to the system clock.
type Clock = timex.Clock

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

	// SubjectProjector maps the OP-internal subject onto the "sub" the
	// client sees in its id_token. A non-identity projection makes an
	// id_token_hint's sub unusable as an internal subject, so such
	// requests are refused. A nil projector is the identity.
	SubjectProjector func(ctx context.Context, raw string, client *store.Client) (string, error)

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
	return audit.OrDiscard(d.Audit)
}

// now returns the wall-clock reading for this request, falling
// back to the system clock when [Deps.Clock] is nil.
func (d *Deps) now() time.Time {
	return timex.OrSystem(d.Clock).Now()
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
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if deps.CIBARequests == nil {
			httpx.StampNoStore(w)
			endpointsupport.WriteOAuthError(w, http.StatusInternalServerError, errServerError,
				"backchannel-authentication substore is not configured")
			return
		}
		serve(w, r, deps)
	})
}

// serve is the request-scoped entry point. It validates the
// request shape, authenticates the client, classifies the hint,
// resolves it to a subject, parses the requested parameters,
// mints the auth_req_id, and persists the resulting record.
//
// The gates are enumerated in flat shape so each one maps onto the
// CIBA Core clause it enforces; folding them into helpers would
// obscure the request ordering. The exception is the parameter-parsing
// tail (acr_values through client_notification_token), extracted into
// [parseRemainingParams] to stay under the linter's complexity budget;
// it runs the same gates in the same order.
func serve(w http.ResponseWriter, r *http.Request, deps Deps) {
	if !parseAndValidateForm(w, r) {
		return
	}
	dpopJKT, client, ok := authenticateWithDPoP(w, r, deps)
	if !ok {
		return
	}
	mtlsThumbprint, ok := endpointsupport.ExtractMTLSThumbprint(w, r, deps.MTLS)
	if !ok {
		return
	}
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
	resource, ok := endpointsupport.ParseSingleResource(w, merged, client, "backchannel-authentication endpoint")
	if !ok {
		return
	}
	params, ok := parseRemainingParams(w, deps, merged)
	if !ok {
		return
	}
	persist(r.Context(), w, deps, persistInput{
		Client:         client,
		Subject:        subject,
		HintKind:       hintKind,
		Scope:          scope,
		Resource:       resource,
		ACRValues:      params.ACRValues,
		BindingMessage: params.BindingMessage,
		UserCode:       params.UserCode,
		ExpiresIn:      params.ExpiresIn,
		DPoPJKT:        dpopJKT,
		MTLSThumbprint: mtlsThumbprint,
	})
}

// parseAndValidateForm runs the request-shape gates that must clear
// before any cryptographic or business work (CIBA Core §7.1 inherits
// the RFC 6749 §3.2 single-valued rule). On failure the wire envelope is
// already written and the function returns false.
func parseAndValidateForm(w http.ResponseWriter, r *http.Request) bool {
	return endpointsupport.ParseFormRequest(w, r, cibaSingleValuedParams)
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

// emitRejected records a /bc-authorize rejection on the audit stream.
// detail completes the event message and reason is a stable code
// string; the wire response carries less detail on purpose, so the
// audit event is where an operator learns which gate closed.
func emitRejected(ctx context.Context, deps Deps, clientID, detail, reason string) {
	deps.auditEmitter().Emit(ctx, audit.Event{
		Name:     ciba.AuditAuthorizationRejected,
		Level:    audit.LevelWarn,
		Message:  "backchannel-authentication rejected: " + detail,
		ClientID: clientID,
		Extras:   map[string]any{"reason": reason},
	})
}
