// Package clientauthhttp wires the [clientauth] verifier into an
// HTTP boundary helper shared by the token and PAR endpoints. The
// surfaces both run an identical "parse credentials → look up
// client → verify → emit audit on failure → write canonical RFC 6749
// §5.2 envelope" pipeline; without this package the two would
// duplicate ~150 lines of error-mapping and audit code that drifts
// silently when one side is updated.
//
// The package is intentionally small: it owns the boundary mapping
// and the canonical wire envelope, but defers credential parsing,
// secret hashing, and assertion verification to [clientauth] —
// which knows nothing about HTTP.
package clientauthhttp

import (
	"context"
	"errors"
	"net/http"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/httpx"
	"github.com/libraz/go-oidc-provider/op/store"
)

// RFC 6749 §5.2 wire codes the helper emits. The set is closed; ad-hoc
// codes are forbidden so the discoverable error surface stays
// auditable across endpoints.
const (
	codeInvalidRequest = "invalid_request"
	codeInvalidClient  = "invalid_client"
	codeServerError    = "server_error"
)

// EventClientAuthnFailure is the canonical audit-event name emitted on
// any pre-issuance client authentication failure (RFC 6749 §5.2). The
// constant lives here because [Authenticate] is the single emission
// site shared by every endpoint that runs the credential pipeline; the
// per-endpoint packages reference this name to keep the audit stream
// uniform. The string is mirrored verbatim by [op.AuditClientAuthnFailure];
// op/audit_test.go pins the equality so the public catalog cannot drift.
const EventClientAuthnFailure = "client_authn.failure"

// Authenticator is a per-endpoint client-auth driver. The caller
// wires the verifier knobs at construction; a single [Authenticate]
// call resolves credentials, looks up the client, runs the verifier,
// and on failure writes the canonical RFC 6749 §5.2 envelope before
// returning ok=false. The wiring lives outside the per-endpoint
// handler so the token / PAR / introspection / revocation surfaces
// share an identical authentication contract — a divergence between
// any two would be a profile-conformance bug.
//
// The struct is deliberately a bag of fields rather than a
// constructor: the per-endpoint Deps already holds a [SecretVerifier]
// and an [AssertionVerifier], so building the value at handler
// construction time is a one-line literal and avoids a second
// per-request allocation.
type Authenticator struct {
	// Clients is the read-only client registry. The helper looks the
	// authenticated client_id up here before delegating to the
	// verifier.
	Clients store.ClientStore

	// SecretVerifier verifies confidential-client secrets. Optional —
	// a nil value defers to the per-endpoint Deps (which itself
	// installs [clientauth.Argon2id] when omitted).
	SecretVerifier clientauth.SecretVerifier

	// AssertionVerifier verifies private_key_jwt assertions. A nil
	// value disables private_key_jwt support: requests that arrive
	// with a "client_assertion" parameter are rejected as
	// invalid_client.
	AssertionVerifier clientauth.AssertionVerifier

	// AllowedMethods optionally restricts which client authentication
	// methods the endpoint accepts, regardless of the registered
	// client's stored TokenEndpointAuthMethod. Empty means "no
	// restriction"; non-empty means the chosen method must appear in
	// the list or the request fails with invalid_client.
	AllowedMethods []clientauth.Method

	// Audit is the structured audit-event sink. A nil emitter falls
	// back to [audit.Discard] so call sites can invoke Emit
	// unconditionally.
	Audit audit.Emitter

	// AuditEventName is the [audit.Event.Name] string the helper
	// stamps on every "client_authn.failure" emission. Defaults to
	// "client_authn.failure" when empty so a default-constructed
	// Authenticator behaves like the canonical wiring; the field is
	// parameterised so subsequent surfaces (introspect / revoke) can
	// pin a distinct name when they grow per-endpoint dispatch.
	AuditEventName string

	// AuditMessage is the [audit.Event.Message] string the helper
	// stamps on every "client_authn.failure" emission. Defaults to
	// "client authentication failed" when empty; the per-endpoint
	// handler typically pins a more specific value (e.g. "at token
	// endpoint" / "at PAR endpoint") so SOC tooling can grep on the
	// surface that fired the failure.
	AuditMessage string
}

const (
	defaultAuditEventName = "client_authn.failure"
	defaultAuditMessage   = "client authentication failed"
)

// Authenticate runs the parse → lookup → verify pipeline. On success
// it returns the resolved client + parsed credentials. On failure it
// has already written the wire response and returns ok=false; the
// caller only checks the bool. Each failure path raises a
// [audit.Event] (named per [Authenticator.AuditEventName]) carrying
// the attempted client_id (when known), the parsed auth method (when
// known), and a short reason code so SOC tooling can distinguish
// "wrong secret" from "unknown client" probing patterns even though
// the wire response stays at the canonical RFC 6749 §5.2
// "invalid_client" envelope.
func (a *Authenticator) Authenticate(ctx context.Context, w http.ResponseWriter, r *http.Request) (*store.Client, *clientauth.Credentials, bool) {
	creds, err := clientauth.Parse(r)
	usedBasic := r.Header.Get("Authorization") != ""
	if err != nil {
		a.emitClientAuthnFailure(ctx, "", "", reasonForAuthnError(err))
		writeAuthnError(w, err, usedBasic)
		return nil, nil, false
	}
	if creds.Method == clientauth.MethodPrivateKeyJWT && a.AssertionVerifier == nil {
		a.emitClientAuthnFailure(ctx, creds.ClientID, string(creds.Method), "private_key_jwt_disabled")
		writeInvalidClient(w, usedBasic, "private_key_jwt is not enabled")
		return nil, nil, false
	}
	client, err := a.lookupClient(ctx, creds.ClientID)
	if err != nil {
		a.emitClientAuthnFailure(ctx, creds.ClientID, string(creds.Method), reasonForAuthnError(err))
		writeAuthnError(w, err, usedBasic)
		return nil, nil, false
	}
	if _, err := clientauth.VerifyClient(ctx, creds, client, clientauth.VerifyOpts{
		SecretVerifier:    a.SecretVerifier,
		AssertionVerifier: a.AssertionVerifier,
		AllowedMethods:    a.AllowedMethods,
	}); err != nil {
		a.emitClientAuthnFailure(ctx, creds.ClientID, string(creds.Method), reasonForAuthnError(err))
		writeAuthnError(w, err, usedBasic)
		return nil, nil, false
	}
	return client, creds, true
}

// emitClientAuthnFailure raises [audit.Event] for a pre-issuance
// client authentication failure. The wire response stays on the
// canonical RFC 6749 §5.2 "invalid_client" envelope, so the audit
// stream is the only place the failing client_id and a triage-level
// reason code surface.
func (a *Authenticator) emitClientAuthnFailure(ctx context.Context, clientID, method, reason string) {
	extras := map[string]any{"reason": reason}
	if method != "" {
		extras["method"] = method
	}
	a.emitter().Emit(ctx, audit.Event{
		Name:     a.eventName(),
		Level:    audit.LevelWarn,
		Message:  a.message(),
		ClientID: clientID,
		Extras:   extras,
	})
}

// emitter returns the configured audit sink, falling back to
// [audit.Discard] so call sites can invoke Emit unconditionally.
func (a *Authenticator) emitter() audit.Emitter {
	if a.Audit == nil {
		return audit.Discard()
	}
	return a.Audit
}

// eventName returns the canonical event name, defaulting when the
// caller omitted it.
func (a *Authenticator) eventName() string {
	if a.AuditEventName == "" {
		return defaultAuditEventName
	}
	return a.AuditEventName
}

// message returns the canonical event message, defaulting when the
// caller omitted it.
func (a *Authenticator) message() string {
	if a.AuditMessage == "" {
		return defaultAuditMessage
	}
	return a.AuditMessage
}

// lookupClient resolves the registered client for id, mapping
// [store.ErrNotFound] to [clientauth.ErrCredentialsInvalid] so the
// caller cannot tell "unknown client" apart from "wrong secret"
// through the error surface.
func (a *Authenticator) lookupClient(ctx context.Context, id string) (*store.Client, error) {
	if id == "" {
		return nil, clientauth.ErrCredentialsInvalid
	}
	c, err := a.Clients.GetClient(ctx, id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, clientauth.ErrCredentialsInvalid
		}
		return nil, err
	}
	return c, nil
}

// reasonForAuthnError maps a [clientauth] sentinel onto the short
// reason code emitted on the audit event. The codes match the
// clientauth error names so a reader can grep from an audit line
// back to the failing branch in the verifier.
func reasonForAuthnError(err error) string {
	switch {
	case errors.Is(err, clientauth.ErrNoCredentials):
		return "no_credentials"
	case errors.Is(err, clientauth.ErrAmbiguousCredentials):
		return "ambiguous_credentials"
	case errors.Is(err, clientauth.ErrUnsupportedMethod):
		return "unsupported_method"
	case errors.Is(err, clientauth.ErrClientMismatch):
		return "client_mismatch"
	case errors.Is(err, clientauth.ErrCredentialsInvalid):
		return "invalid_client_credentials"
	case errors.Is(err, clientauth.ErrAssertionMalformed):
		return "assertion_malformed"
	case errors.Is(err, clientauth.ErrAssertionReplayed):
		return "assertion_replayed"
	default:
		return "server_error"
	}
}

// writeAuthnError maps an authentication error onto the wire
// response. The mapping is the canonical RFC 6749 §5.2 table
// augmented by this library's sentinel discrimination.
func writeAuthnError(w http.ResponseWriter, err error, usedBasic bool) {
	switch {
	case errors.Is(err, clientauth.ErrNoCredentials):
		// No credentials at all: the request reached the endpoint
		// without any way to authenticate a confidential client and
		// without claiming a public-client identity. Surface 401 with
		// a challenge so RP libraries retry intelligently.
		writeInvalidClient(w, usedBasic, "client authentication required")
	case errors.Is(err, clientauth.ErrAmbiguousCredentials),
		errors.Is(err, clientauth.ErrUnsupportedMethod):
		_ = httpx.WriteError(w, http.StatusBadRequest, codeInvalidRequest,
			"client authentication parameters are malformed")
	case errors.Is(err, clientauth.ErrClientMismatch),
		errors.Is(err, clientauth.ErrCredentialsInvalid),
		errors.Is(err, clientauth.ErrAssertionMalformed),
		errors.Is(err, clientauth.ErrAssertionReplayed):
		writeInvalidClient(w, usedBasic, "client authentication failed")
	default:
		_ = httpx.WriteError(w, http.StatusInternalServerError, codeServerError, "")
	}
}

// writeInvalidClient is the dedicated 401 path for the
// "invalid_client" code: per RFC 6749 §5.2, a request that
// authenticated via HTTP Basic MUST receive a WWW-Authenticate
// challenge so RP libraries that follow the Basic-auth state machine
// retry intelligently. The realm value is fixed to "oidc" to match
// the rest of the library's posture.
func writeInvalidClient(w http.ResponseWriter, basic bool, description string) {
	if basic {
		w.Header().Set("WWW-Authenticate", `Basic realm="oidc"`)
	}
	_ = httpx.WriteError(w, http.StatusUnauthorized, codeInvalidClient, description)
}
