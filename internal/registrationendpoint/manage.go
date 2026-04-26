package registrationendpoint

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/libraz/go-oidc-provider/op/store"
)

// handleRead implements GET /register/{client_id} (RFC 7592 §2.1). On
// success the handler returns the same body shape as POST /register
// minus the registration_access_token: per spec, the client retains
// the RAT issued at creation time and the OP does not re-issue it
// here.
func handleRead(w http.ResponseWriter, r *http.Request, deps Deps, clientID string) {
	ctx := r.Context()
	client, ok := verifyRAT(ctx, w, r, deps, clientID)
	if !ok {
		return
	}
	deps.audit().Audit(ctx, auditEvent{
		Name:     auditDCRClientMetadataRead,
		Level:    auditLevelInfo,
		Message:  "client metadata read via RFC 7592",
		ClientID: clientID,
	})
	writeRegistrationResponse(w, http.StatusOK, clientToResponse(client, deps, "" /* no rotated RAT */))
}

// handleUpdate implements PUT /register/{client_id} (RFC 7592 §2.2).
// The handler accepts the same metadata shape as POST /register, runs
// the same validators, rotates the RAT (per
// docs/plans/002-product-design.md §A.6.2.2 peer divergence), and
// updates the client.
func handleUpdate(w http.ResponseWriter, r *http.Request, deps Deps, clientID string) {
	ctx := r.Context()
	existing, ok := verifyRAT(ctx, w, r, deps, clientID)
	if !ok {
		return
	}
	if !isJSONContent(r.Header.Get("Content-Type")) {
		writeRegistrationError(w, http.StatusBadRequest, codeInvalidRequest,
			"content-type must be application/json")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	metadata, extras, err := parseClientMetadataWithExtras(r.Body)
	if err != nil {
		writeRegistrationError(w, http.StatusBadRequest, codeInvalidClientMetadata, "malformed JSON")
		return
	}
	if extras.SoftwareStatement != "" {
		writeRegistrationError(w, http.StatusBadRequest, codeInvalidSoftwareStmt,
			"software_statement is not supported in v1.0")
		return
	}
	if extras.ClientID != "" && extras.ClientID != clientID {
		writeRegistrationError(w, http.StatusBadRequest, codeInvalidClientMetadata,
			"client_id is immutable")
		return
	}
	canonical, err := validatePolicy(
		metadata,
		deps.AllowedGrantTypes,
		deps.AllowedResponseTypes,
		nil, // PUT path does not re-check IAT scopes (the IAT was consumed at creation).
		deps.Scopes,
		deps.PairwiseEnabled,
	)
	if err != nil {
		writeMetadataValidationError(ctx, w, deps, err, clientID)
		return
	}
	if deps.ValidateMetadata != nil {
		if hookErr := deps.ValidateMetadata(ctx, canonical); hookErr != nil {
			writeMetadataValidationError(ctx, w, deps, hookErr, clientID)
			return
		}
	}
	rotated, ok := rotateAndUpdate(ctx, w, deps, existing, canonical)
	if !ok {
		return
	}
	deps.audit().Audit(ctx, auditEvent{
		Name:     auditDCRClientMetadataUpdated,
		Level:    auditLevelInfo,
		Message:  "client metadata updated via RFC 7592",
		ClientID: clientID,
	})
	writeRegistrationResponse(w, http.StatusOK, clientToResponse(rotated.client, deps, rotated.rawRAT))
}

// rotateAndUpdate is the shared persistence path for PUT
// /register/{client_id}. It mints a fresh RAT, persists the updated
// client, and overwrites the RAT row. The function returns the
// updated client plus the raw RAT so the caller can include it in the
// response body.
type rotatedRegistration struct {
	client *store.Client
	rawRAT string
}

func rotateAndUpdate(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	existing *store.Client,
	m ClientMetadata,
) (rotatedRegistration, bool) {
	rawRAT, err := newOpaqueID(ratBytes)
	if err != nil {
		deps.logger().Error("dcr.rat.generate_failed", "err", err, "client_id", existing.ID)
		writeRegistrationError(w, http.StatusInternalServerError, codeServerError, "")
		return rotatedRegistration{}, false
	}
	confidential := isConfidentialAuthMethod(m.TokenEndpointAuthMethod)
	updated := &store.Client{
		ID:                      existing.ID,
		RedirectURIs:            slices.Clone(m.RedirectURIs),
		GrantTypes:              slices.Clone(m.GrantTypes),
		ResponseTypes:           slices.Clone(m.ResponseTypes),
		Scopes:                  splitScopes(m.Scope),
		TokenEndpointAuthMethod: m.TokenEndpointAuthMethod,
		// Preserve the existing secret hash unless the
		// auth-method change requires a fresh secret. RFC 7592
		// §2.2 leaves rotation policy to the OP; the conservative
		// posture is to keep the secret stable so the RP does not
		// have to roll over after every metadata edit. A genuine
		// secret rotation is a separate operator-initiated action
		// (out of scope for v1.0).
		SecretHash:               secretHashForUpdate(existing, confidential),
		PublicClient:             !confidential,
		Source:                   store.ClientSourceDynamic,
		ApplicationType:          m.ApplicationType,
		SubjectType:              m.SubjectType,
		IDTokenSignedResponseAlg: m.IDTokenSignedResponseAlg,
		SectorIdentifierURI:      m.SectorIdentifierURI,
		ClientName:               m.ClientName,
		ClientURI:                m.ClientURI,
		LogoURI:                  m.LogoURI,
		PolicyURI:                m.PolicyURI,
		TosURI:                   m.TosURI,
		JWKsURI:                  m.JWKsURI,
		JWKs:                     append(json.RawMessage(nil), m.JWKs...),
		Contacts:                 slices.Clone(m.Contacts),
		DefaultMaxAge:            m.DefaultMaxAge,
		RequireAuthTime:          m.RequireAuthTime,
		DefaultACRValues:         slices.Clone(m.DefaultACRValues),
		InitiateLoginURI:         m.InitiateLoginURI,
		RequestURIs:              slices.Clone(m.RequestURIs),
	}
	if err := deps.Clients.UpdateClient(ctx, updated); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// Race: the client was deleted between RAT verify and
			// update. Surface the same invalid_token response so
			// enumeration cannot tell "deleted" apart from "RAT
			// invalid".
			writeInvalidToken(w, deps.Issuer, "registration access token is invalid")
			return rotatedRegistration{}, false
		}
		deps.logger().Error("dcr.client.update_failed", "err", err, "client_id", existing.ID)
		writeRegistrationError(w, http.StatusInternalServerError, codeServerError, "")
		return rotatedRegistration{}, false
	}
	now := deps.now().UTC()
	ratRec := &store.RegistrationAccessToken{
		ClientID:    existing.ID,
		HashedValue: hashSecret(rawRAT),
		CreatedAt:   now,
	}
	if err := deps.RegistrationAccessTokens.Put(ctx, ratRec); err != nil {
		deps.logger().Error("dcr.rat.put_failed", "err", err, "client_id", existing.ID)
		writeRegistrationError(w, http.StatusInternalServerError, codeServerError, "")
		return rotatedRegistration{}, false
	}
	return rotatedRegistration{client: updated, rawRAT: rawRAT}, true
}

// secretHashForUpdate decides which secret hash the updated client
// record should carry. Switching from confidential to public clears
// the hash; switching from public to confidential without minting a
// fresh secret is a configuration error, but the library still
// accepts the update — the next /token request will simply fail to
// authenticate, which is a clearer signal to the operator than a 400
// at update time.
func secretHashForUpdate(existing *store.Client, confidential bool) string {
	if !confidential {
		return ""
	}
	return existing.SecretHash
}

// handleDelete implements DELETE /register/{client_id} (RFC 7592 §2.3).
// The handler revokes the RAT, deletes the client, and returns 204.
// Existing access_token / refresh_token / session revocation is
// documented in §A.6.2.2 as the desired behaviour but is left as a
// TODO in v1.0 because the cross-cutting revocation orchestration
// requires the back-channel logout subsystem to be wired first.
func handleDelete(w http.ResponseWriter, r *http.Request, deps Deps, clientID string) {
	ctx := r.Context()
	if _, ok := verifyRAT(ctx, w, r, deps, clientID); !ok {
		return
	}
	if err := deps.RegistrationAccessTokens.Delete(ctx, clientID); err != nil && !errors.Is(err, store.ErrNotFound) {
		deps.logger().Error("dcr.rat.delete_failed", "err", err, "client_id", clientID)
		writeRegistrationError(w, http.StatusInternalServerError, codeServerError, "")
		return
	}
	if err := deps.Clients.DeleteClient(ctx, clientID); err != nil && !errors.Is(err, store.ErrNotFound) {
		deps.logger().Error("dcr.client.delete_failed", "err", err, "client_id", clientID)
		writeRegistrationError(w, http.StatusInternalServerError, codeServerError, "")
		return
	}
	// TODO: revoke outstanding access_token / refresh_token / session
	// records and emit Back-Channel logout per
	// docs/plans/002-product-design.md §A.6.2.2. The cross-cutting
	// revocation orchestration requires the back-channel logout
	// subsystem to be wired first.
	deps.audit().Audit(ctx, auditEvent{
		Name:     auditDCRClientDeleted,
		Level:    auditLevelInfo,
		Message:  "client deleted via RFC 7592",
		ClientID: clientID,
	})
	stampNoStore(w)
	w.WriteHeader(http.StatusNoContent)
}

// clientToResponse projects a [store.Client] back onto the RFC 7591
// §3.2.1 response shape. The function is shared by handleRead and
// handleUpdate; rotatedRAT is the freshly minted RAT for the update
// path and "" for reads. Every metadata field the persistent record
// carries is echoed so an RFC 7592 round-trip preserves the values
// the client originally registered.
func clientToResponse(c *store.Client, deps Deps, rotatedRAT string) registrationResponse {
	return registrationResponse{
		ClientID:                c.ID,
		ClientIDIssuedAt:        0,
		ClientSecretExpiresAt:   0,
		RegistrationAccessToken: rotatedRAT,
		RegistrationClientURI:   registrationClientURI(deps.Issuer, deps.MountPrefix, deps.RegisterPath, c.ID),
		RedirectURIs:            slices.Clone(c.RedirectURIs),
		GrantTypes:              slices.Clone(c.GrantTypes),
		ResponseTypes:           slices.Clone(c.ResponseTypes),
		Scope:                   strings.Join(c.Scopes, " "),
		TokenEndpointAuthMethod: c.TokenEndpointAuthMethod,
		ApplicationType:         c.ApplicationType,
		SubjectType:             c.SubjectType,
		IDTokenAlg:              c.IDTokenSignedResponseAlg,
		ClientName:              c.ClientName,
		ClientURI:               c.ClientURI,
		LogoURI:                 c.LogoURI,
		PolicyURI:               c.PolicyURI,
		TosURI:                  c.TosURI,
		JWKsURI:                 c.JWKsURI,
		Contacts:                slices.Clone(c.Contacts),
		DefaultMaxAge:           c.DefaultMaxAge,
		RequireAuthTime:         c.RequireAuthTime,
		DefaultACRValues:        slices.Clone(c.DefaultACRValues),
		InitiateLoginURI:        c.InitiateLoginURI,
		RequestURIs:             slices.Clone(c.RequestURIs),
	}
}
