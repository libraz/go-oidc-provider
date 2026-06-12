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
	"net/http"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/op/store"
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
	return endpointsupport.AuthenticateClient(ctx, w, r, endpointsupport.AuthenticateOpts{
		Clients:           a.Clients,
		SecretVerifier:    a.SecretVerifier,
		AssertionVerifier: a.AssertionVerifier,
		AllowedMethods:    a.AllowedMethods,
	}, func(creds *clientauth.Credentials, err error) {
		clientID := ""
		method := ""
		if creds != nil {
			clientID = creds.ClientID
			method = string(creds.Method)
		}
		endpointsupport.EmitAuthnFailure(ctx, a.Audit, a.eventName(), a.message(), clientID, err, method)
	})
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
