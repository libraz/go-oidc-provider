package endpointsupport

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/dpop"
	"github.com/libraz/go-oidc-provider/internal/resourceindicator"
	"github.com/libraz/go-oidc-provider/op/store"
)

// Wire codes the grant-initiation helpers emit beyond the base set.
const (
	// ErrUnauthorizedClient is the RFC 6749 §5.2 "client is not allowed
	// to use this grant" code.
	ErrUnauthorizedClient = "unauthorized_client"

	// ErrInvalidTarget is the RFC 8707 §2 "resource is not acceptable"
	// code.
	ErrInvalidTarget = "invalid_target"
)

// AuthenticateWithDPoP runs DPoP proof verification and client
// authentication through the shared [dpop.Gate] and returns the
// proof's RFC 7638 thumbprint ("" when no proof was presented)
// alongside the authenticated client.
//
// The gate documents the verify → authenticate → commit ordering and
// the reasons behind it; every endpoint calling this inherits it
// unchanged. The deferred replay commit matters because the endpoint
// requires a credential: a proof burned on a request that never
// authenticated would make the legitimate retry look like a replay. A
// nil gate verifier admits every request without a proof; whether a
// proof must be presented at all is a separate gate
// ([EnforceSenderConstraint]).
//
// The function writes the response on every failure path; the caller
// only checks the bool.
func AuthenticateWithDPoP(
	w http.ResponseWriter,
	r *http.Request,
	gate dpop.Gate,
	opts AuthenticateOpts,
	failureMessage string,
) (string, *store.Client, bool) {
	var client *store.Client
	checked, ok := gate.Authenticate(r.Context(), w, r, func() bool {
		var authOK bool
		client, _, authOK = AuthenticateClientAudited(r.Context(), w, r, opts, failureMessage)
		return authOK
	})
	if !ok {
		return "", nil, false
	}
	return checked.Thumbprint(), client, true
}

// SenderConstraintRejection names the audit event and wording an
// endpoint uses when [EnforceSenderConstraint] refuses an unbound
// request.
type SenderConstraintRejection struct {
	// Event is the audit event name raised on rejection.
	Event string
	// AuditMessage is the audit event's message.
	AuditMessage string
	// Description is the invalid_request description on the wire.
	Description string
}

// EnforceSenderConstraint applies the FAPI 2.0 rule that no request to
// a grant-initiation endpoint MAY produce a bearer token. When required
// is true and the request carries neither DPoP nor mTLS, it raises the
// audit event, writes invalid_request and returns false.
func EnforceSenderConstraint(
	ctx context.Context,
	w http.ResponseWriter,
	emitter audit.Emitter,
	required bool,
	rej SenderConstraintRejection,
	dpopJKT, mtlsThumbprint, clientID string,
) bool {
	if !required {
		return true
	}
	if dpopJKT != "" || mtlsThumbprint != "" {
		return true
	}
	audit.OrDiscard(emitter).Emit(ctx, audit.Event{
		Name:     rej.Event,
		Level:    audit.LevelWarn,
		Message:  rej.AuditMessage,
		ClientID: clientID,
		Extras: map[string]any{
			"profile": "fapi2_baseline",
			"reason":  "unbound_request",
		},
	})
	WriteOAuthError(w, http.StatusBadRequest, ErrInvalidRequest, rej.Description)
	return false
}

// GrantRejection names the audit event and wording an endpoint uses
// when [VerifyClientGrantType] refuses a client.
type GrantRejection struct {
	// Event is the audit event name raised on rejection.
	Event string
	// AuditMessage is the audit event's message.
	AuditMessage string
	// Description is the unauthorized_client description on the wire.
	Description string
}

// VerifyClientGrantType rejects clients whose registered GrantTypes do
// not include grantURN. The check matches the token-endpoint poll's
// gate so a misconfigured client cannot even initiate the flow. It
// writes unauthorized_client and returns false on rejection.
func VerifyClientGrantType(
	ctx context.Context,
	w http.ResponseWriter,
	emitter audit.Emitter,
	client *store.Client,
	grantURN string,
	rej GrantRejection,
) bool {
	if slices.Contains(client.GrantTypes, grantURN) {
		return true
	}
	audit.OrDiscard(emitter).Emit(ctx, audit.Event{
		Name:     rej.Event,
		Level:    audit.LevelWarn,
		Message:  rej.AuditMessage,
		ClientID: client.ID,
		Extras: map[string]any{
			"reason": "grant_type_not_permitted",
		},
	})
	WriteOAuthError(w, http.StatusBadRequest, ErrUnauthorizedClient, rej.Description)
	return false
}

// InitiationGate bundles the per-endpoint inputs of the grant-initiation
// gates (client authentication, sender-constraint requirement, grant
// registration) so a device-style endpoint builds it once per request.
type InitiationGate struct {
	// DPoP is the proof gate run alongside client authentication.
	DPoP dpop.Gate
	// Auth configures client authentication; Auth.Audit also receives
	// the rejection events.
	Auth AuthenticateOpts
	// AuthFailureMessage is the audit message for a failed authentication.
	AuthFailureMessage string
	// RequireSenderConstraint rejects requests bound to neither DPoP nor mTLS.
	RequireSenderConstraint bool
	// Unbound words the sender-constraint rejection.
	Unbound SenderConstraintRejection
	// GrantURN is the grant type the client must be registered for.
	GrantURN string
	// GrantMissing words the grant-registration rejection.
	GrantMissing GrantRejection
}

// Authenticate runs [AuthenticateWithDPoP] with the gate's inputs.
func (g InitiationGate) Authenticate(w http.ResponseWriter, r *http.Request) (string, *store.Client, bool) {
	return AuthenticateWithDPoP(w, r, g.DPoP, g.Auth, g.AuthFailureMessage)
}

// EnforceSenderConstraint runs [EnforceSenderConstraint] with the gate's inputs.
func (g InitiationGate) EnforceSenderConstraint(
	ctx context.Context,
	w http.ResponseWriter,
	dpopJKT, mtlsThumbprint, clientID string,
) bool {
	return EnforceSenderConstraint(ctx, w, g.Auth.Audit, g.RequireSenderConstraint, g.Unbound,
		dpopJKT, mtlsThumbprint, clientID)
}

// VerifyClientGrantType runs [VerifyClientGrantType] with the gate's inputs.
func (g InitiationGate) VerifyClientGrantType(ctx context.Context, w http.ResponseWriter, client *store.Client) bool {
	return VerifyClientGrantType(ctx, w, g.Auth.Audit, client, g.GrantURN, g.GrantMissing)
}

// BindingLabel returns the audit-extras label naming which sender
// constraint an issued record carries: "dpop", "mtls", or "bearer".
func BindingLabel(dpopJKT, mtlsThumbprint string) string {
	switch {
	case dpopJKT != "":
		return "dpop"
	case mtlsThumbprint != "":
		return "mtls"
	default:
		return "bearer"
	}
}

// ParseSingleResource extracts the RFC 8707 resource indicators from
// form. Parsing, validation and canonicalisation go through
// [resourceindicator.Canonicalize], and each surviving value MUST
// appear in the client's registered Resources allowlist
// ([resourceindicator.Contains], so historical registrations that
// pre-date canonicalisation still match). The issuance pipeline honours
// a single audience entry, so more than one non-empty value is rejected
// with invalid_target rather than silently truncated; endpointName
// completes that message ("... are not supported on the <endpointName>").
// It writes the response and returns false on rejection.
func ParseSingleResource(
	w http.ResponseWriter,
	form url.Values,
	client *store.Client,
	endpointName string,
) ([]string, bool) {
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
			WriteOAuthError(w, http.StatusBadRequest, ErrInvalidTarget,
				"resource parameter is not a valid absolute URI")
			return nil, false
		}
		if !resourceindicator.Contains(client.Resources, canonical) {
			WriteOAuthError(w, http.StatusBadRequest, ErrInvalidTarget,
				"resource is not registered for this client")
			return nil, false
		}
		out = append(out, canonical)
	}
	if len(out) > 1 {
		WriteOAuthError(w, http.StatusBadRequest, ErrInvalidTarget,
			"multiple resource indicators are not supported on the "+endpointName)
		return nil, false
	}
	return out, true
}
