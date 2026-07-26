package registrationendpoint

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/clone"
	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/internal/oidcscope"
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
	deps.audit().Emit(ctx, audit.Event{
		Name:     auditDCRClientMetadataRead,
		Level:    audit.LevelInfo,
		Message:  "client metadata read via RFC 7592",
		ClientID: clientID,
	})
	writeRegistrationResponse(w, http.StatusOK, clientToResponse(client, deps, "" /* no rotated RAT */, "" /* no secret */))
}

// handleUpdate implements PUT /register/{client_id} (RFC 7592 §2.2).
// The handler accepts the same metadata shape as POST /register, runs
// the same validators, rotates the RAT (per
// 02-product-design.md §A.6.2.2 peer divergence), and
// updates the client.
func handleUpdate(w http.ResponseWriter, r *http.Request, deps Deps, clientID string) {
	ctx := r.Context()
	existing, ok := verifyRAT(ctx, w, r, deps, clientID)
	if !ok {
		return
	}
	if !endpointsupport.IsJSONContent(r.Header.Get("Content-Type")) {
		writeRegistrationError(w, http.StatusBadRequest, codeInvalidRequest,
			"content-type must be application/json")
		return
	}
	// The cap matches the token and PAR endpoints so the DCR JSON body
	// shares the same posture as the OAuth form-encoded surfaces (RFC 7591
	// §2 metadata is small, kilobytes at most, so 64 KiB is well above any
	// legitimate payload).
	endpointsupport.LimitFormBody(w, r)
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
	if err := validateManageUpdateRequest(existing, clientID, extras); err != nil {
		writeRegistrationError(w, http.StatusBadRequest, codeInvalidRequest, err.Error())
		return
	}
	canonical, err := validatePolicy(
		metadata,
		deps.AllowedGrantTypes,
		deps.AllowedResponseTypes,
		nil,   // PUT path does not re-check IAT scopes (the IAT was consumed at creation).
		false, // PUT is RAT-authenticated, never the open-registration flow.
		nil,   // PUT path does not apply the open-registration default scope.
		deps.Scopes,
		deps.PairwiseEnabled,
		deps.AllowLocalhostLoopback,
		deps.AllowInsecureBackchannelLogoutForDev,
	)
	if err != nil {
		writeMetadataValidationError(ctx, w, deps, err, clientID)
		return
	}
	if err := validateSectorIdentifierURI(ctx, deps, canonical); err != nil {
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
	deps.audit().Emit(ctx, audit.Event{
		Name:     auditDCRClientMetadataUpdated,
		Level:    audit.LevelInfo,
		Message:  "client metadata updated via RFC 7592",
		ClientID: clientID,
	})
	writeRegistrationResponse(w, http.StatusOK, clientToResponse(rotated.client, deps, rotated.rawRAT, rotated.rawSecret))
}

// rotateAndUpdate is the shared persistence path for PUT
// /register/{client_id}. It mints a fresh RAT, persists the updated
// client, and overwrites the RAT row. The function returns the
// updated client plus the raw RAT so the caller can include it in the
// response body.
type rotatedRegistration struct {
	client    *store.Client
	rawRAT    string
	rawSecret string
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
	rawSecret, secretHash, err := secretMaterialForUpdate(existing, confidential)
	if err != nil {
		deps.logger().Error("dcr.client_secret.generate_failed", "err", err, "client_id", existing.ID)
		writeRegistrationError(w, http.StatusInternalServerError, codeServerError, "")
		return rotatedRegistration{}, false
	}
	updated := &store.Client{
		ID:                          existing.ID,
		ClientIDIssuedAt:            existing.ClientIDIssuedAt,
		RedirectURIs:                slices.Clone(m.RedirectURIs),
		GrantTypes:                  slices.Clone(m.GrantTypes),
		ResponseTypes:               slices.Clone(m.ResponseTypes),
		Scopes:                      oidcscope.Parse(m.Scope),
		TokenEndpointAuthMethod:     m.TokenEndpointAuthMethod,
		TokenEndpointAuthSigningAlg: m.TokenEndpointAuthSigningAlg,
		// Preserve the existing secret hash unless the
		// auth-method change requires a fresh secret. RFC 7592
		// §2.2 leaves rotation policy to the OP; the conservative
		// posture is to keep the secret stable so the RP does not
		// have to roll over after every metadata edit. A genuine
		// secret rotation is a separate operator-initiated action
		// (out of scope for v1.0).
		SecretHash:                        secretHash,
		PublicClient:                      isPublicAuthMethod(m.TokenEndpointAuthMethod),
		Source:                            store.ClientSourceDynamic,
		ApplicationType:                   m.ApplicationType,
		SubjectType:                       m.SubjectType,
		IDTokenSignedResponseAlg:          m.IDTokenSignedResponseAlg,
		SectorIdentifierURI:               m.SectorIdentifierURI,
		ClientName:                        m.ClientName,
		ClientURI:                         m.ClientURI,
		LogoURI:                           m.LogoURI,
		PolicyURI:                         m.PolicyURI,
		TosURI:                            m.TosURI,
		JWKsURI:                           m.JWKsURI,
		JWKs:                              append(json.RawMessage(nil), m.JWKs...),
		Contacts:                          slices.Clone(m.Contacts),
		DefaultMaxAge:                     clone.Int64Ptr(m.DefaultMaxAge),
		RequireAuthTime:                   m.RequireAuthTime,
		DefaultACRValues:                  slices.Clone(m.DefaultACRValues),
		InitiateLoginURI:                  m.InitiateLoginURI,
		RequestURIs:                       slices.Clone(m.RequestURIs),
		RequestObjectSigningAlg:           m.RequestObjectSigningAlg,
		RequestObjectEncryptionAlg:        m.RequestObjectEncryptionAlg,
		RequestObjectEncryptionEnc:        m.RequestObjectEncryptionEnc,
		IDTokenEncryptedResponseAlg:       m.IDTokenEncryptedResponseAlg,
		IDTokenEncryptedResponseEnc:       m.IDTokenEncryptedResponseEnc,
		UserInfoEncryptedResponseAlg:      m.UserInfoEncryptedResponseAlg,
		UserInfoEncryptedResponseEnc:      m.UserInfoEncryptedResponseEnc,
		AuthorizationEncryptedResponseAlg: m.AuthorizationEncryptedResponseAlg,
		AuthorizationEncryptedResponseEnc: m.AuthorizationEncryptedResponseEnc,
		IntrospectionEncryptedResponseAlg: m.IntrospectionEncryptedResponseAlg,
		IntrospectionEncryptedResponseEnc: m.IntrospectionEncryptedResponseEnc,
		PostLogoutRedirectURIs:            slices.Clone(m.PostLogoutRedirectURIs),
		BackchannelLogoutURI:              m.BackchannelLogoutURI,
		BackchannelLogoutSessionRequired:  m.BackchannelLogoutSessionRequired,
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
		// Best-effort rollback of the metadata update so a partial
		// write (new metadata + missing rotated RAT) does not
		// silently land. The register path runs the symmetric
		// rollback by deleting the freshly inserted client; the
		// management path restores the prior `existing` snapshot
		// because the client_id was already in the registry. Errors
		// here are logged but not surfaced to the caller — the
		// original 500 is the source of truth and a double failure
		// is the rare path operator audit must reconcile manually.
		if rollbackErr := deps.Clients.UpdateClient(ctx, existing); rollbackErr != nil {
			deps.logger().Error("dcr.client.update_rollback_failed",
				"err", rollbackErr, "client_id", existing.ID)
		}
		writeRegistrationError(w, http.StatusInternalServerError, codeServerError, "")
		return rotatedRegistration{}, false
	}
	return rotatedRegistration{client: updated, rawRAT: rawRAT, rawSecret: rawSecret}, true
}

func validateManageUpdateRequest(existing *store.Client, clientID string, extras metadataExtras) error {
	switch {
	case len(extras.RegAccessToken) != 0:
		return errors.New("request MUST NOT include the registration_access_token field")
	case len(extras.RegClientURI) != 0:
		return errors.New("request MUST NOT include the registration_client_uri field")
	case len(extras.ClientSecretExp) != 0:
		return errors.New("request MUST NOT include the client_secret_expires_at field")
	case len(extras.ClientIDIssuedAt) != 0:
		return errors.New("request MUST NOT include the client_id_issued_at field")
	}
	if extras.ClientID != "" && extras.ClientID != clientID {
		return errors.New("client_id is immutable")
	}
	if len(extras.ClientSecret) != 0 {
		if err := validateManageClientSecret(existing, extras.ClientSecret); err != nil {
			return err
		}
	}
	return nil
}

func validateManageClientSecret(existing *store.Client, raw json.RawMessage) error {
	const mismatch = "provided client_secret does not match the authenticated client's one"
	if string(raw) == "null" {
		return errors.New(mismatch)
	}
	var presented string
	if err := json.Unmarshal(raw, &presented); err != nil {
		return errors.New(mismatch)
	}
	if existing == nil || existing.SecretHash == "" {
		return errors.New(mismatch)
	}
	if err := (&clientauth.Argon2id{}).Verify(presented, existing.SecretHash); err != nil {
		return errors.New(mismatch)
	}
	return nil
}

// secretMaterialForUpdate decides which secret material the updated
// client record should carry. Switching from confidential to public
// clears the hash. Switching from public to confidential mints a
// fresh client_secret and returns both the raw value (for the RFC
// 7592 response body) and its hash (for persistence). Confidential
// to confidential updates preserve the existing hash so metadata
// edits do not silently rotate credentials.
func secretMaterialForUpdate(existing *store.Client, confidential bool) (raw, hash string, err error) {
	if !confidential {
		return "", "", nil
	}
	if existing == nil {
		return "", "", errors.New("registrationendpoint: existing client is required for secret update")
	}
	if existing.SecretHash == "" {
		raw, hash, err := newClientSecret()
		if err != nil {
			return "", "", err
		}
		return raw, hash, nil
	}
	return "", existing.SecretHash, nil
}

// handleDelete implements DELETE /register/{client_id} (RFC 7592 §2.3).
// The handler revokes the RAT, deletes the client, invokes the
// embedder-supplied [Deps.OnClientDeleted] cascade hook, and returns
// 204. The library does not perform a built-in cascade because the
// store surfaces required to enumerate access_token / refresh_token /
// session records keyed by client are not part of v1.0 — embedders
// that maintain those indexes wire the cascade through the hook;
// 02-product-design.md §A.6.2.2 captures the eventual
// shape.
func handleDelete(w http.ResponseWriter, r *http.Request, deps Deps, clientID string) {
	ctx := r.Context()
	if _, ok := verifyRAT(ctx, w, r, deps, clientID); !ok {
		return
	}
	// Delete the client record first, then the RAT. The reverse
	// order produces the unrecoverable state "RAT gone, client
	// alive": the RP gets a 500 but can no longer invoke the
	// management endpoint to retry. This order keeps the client /
	// RAT pair recoverable in every failure shape:
	//   - client delete fails  → nothing else touched, RP retries.
	//   - client delete OK,
	//     RAT delete fails     → client is gone (the goal); the RAT row
	//                             is harmless garbage because no client
	//                             can authenticate to it. Logged so the
	//                             operator garbage-collects on schedule.
	if err := deps.Clients.DeleteClient(ctx, clientID); err != nil && !errors.Is(err, store.ErrNotFound) {
		deps.logger().Error("dcr.client.delete_failed", "err", err, "client_id", clientID)
		writeRegistrationError(w, http.StatusInternalServerError, codeServerError, "")
		return
	}
	if err := deps.RegistrationAccessTokens.Delete(ctx, clientID); err != nil && !errors.Is(err, store.ErrNotFound) {
		// Client is already gone; logging the orphan RAT lets the
		// operator clean it up out-of-band. The RP still observes
		// the 204 because the registration is, from its perspective,
		// fully removed.
		deps.logger().Error("dcr.rat.delete_failed_orphan", "err", err, "client_id", clientID)
	}
	// In-tree cascade: probe optional [store.RevokeByClient]
	// implementations on the supplied refresh / grant substores so a
	// deleted client takes its outstanding tokens / consent with it
	// without requiring the embedder to hand-roll the cascade.
	// Backends that do not implement the optional interface fall
	// through silently, preserving the prior behaviour.
	cascadeRevokeByClient(ctx, deps, clientID)
	if deps.OnClientDeleted != nil {
		if err := deps.OnClientDeleted(ctx, clientID); err != nil {
			// Cascade failure does not roll the deletion back: the
			// client record is already gone and re-creating it under
			// the same id would clash with the RFC 7591 §3 contract.
			// Log and proceed so the RP still observes the 204.
			deps.logger().Error("dcr.client.cascade_failed", "err", err, "client_id", clientID)
		}
	}
	deps.audit().Emit(ctx, audit.Event{
		Name:     auditDCRClientDeleted,
		Level:    audit.LevelInfo,
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
func clientToResponse(c *store.Client, deps Deps, rotatedRAT, rawSecret string) registrationResponse {
	return registrationResponse{
		ClientID:                          c.ID,
		ClientIDIssuedAt:                  c.ClientIDIssuedAt,
		ClientSecret:                      rawSecret,
		ClientSecretExpiresAt:             0,
		RegistrationAccessToken:           rotatedRAT,
		RegistrationClientURI:             registrationClientURI(deps.Issuer, deps.MountPrefix, deps.RegisterPath, c.ID),
		RedirectURIs:                      slices.Clone(c.RedirectURIs),
		GrantTypes:                        slices.Clone(c.GrantTypes),
		ResponseTypes:                     slices.Clone(c.ResponseTypes),
		Scope:                             strings.Join(c.Scopes, " "),
		TokenEndpointAuthMethod:           c.TokenEndpointAuthMethod,
		TokenEndpointAuthSigningAlg:       c.TokenEndpointAuthSigningAlg,
		ApplicationType:                   c.ApplicationType,
		SubjectType:                       c.SubjectType,
		IDTokenAlg:                        c.IDTokenSignedResponseAlg,
		SectorIdentifierURI:               c.SectorIdentifierURI,
		ClientName:                        c.ClientName,
		ClientURI:                         c.ClientURI,
		LogoURI:                           c.LogoURI,
		PolicyURI:                         c.PolicyURI,
		TosURI:                            c.TosURI,
		JWKsURI:                           c.JWKsURI,
		JWKs:                              append(json.RawMessage(nil), c.JWKs...),
		Contacts:                          slices.Clone(c.Contacts),
		DefaultMaxAge:                     clone.Int64Ptr(c.DefaultMaxAge),
		RequireAuthTime:                   c.RequireAuthTime,
		DefaultACRValues:                  slices.Clone(c.DefaultACRValues),
		InitiateLoginURI:                  c.InitiateLoginURI,
		RequestURIs:                       slices.Clone(c.RequestURIs),
		RequestObjectSigningAlg:           c.RequestObjectSigningAlg,
		RequestObjectEncryptionAlg:        c.RequestObjectEncryptionAlg,
		RequestObjectEncryptionEnc:        c.RequestObjectEncryptionEnc,
		IDTokenEncryptedResponseAlg:       c.IDTokenEncryptedResponseAlg,
		IDTokenEncryptedResponseEnc:       c.IDTokenEncryptedResponseEnc,
		UserInfoEncryptedResponseAlg:      c.UserInfoEncryptedResponseAlg,
		UserInfoEncryptedResponseEnc:      c.UserInfoEncryptedResponseEnc,
		AuthorizationEncryptedResponseAlg: c.AuthorizationEncryptedResponseAlg,
		AuthorizationEncryptedResponseEnc: c.AuthorizationEncryptedResponseEnc,
		IntrospectionEncryptedResponseAlg: c.IntrospectionEncryptedResponseAlg,
		IntrospectionEncryptedResponseEnc: c.IntrospectionEncryptedResponseEnc,
		PostLogoutRedirectURIs:            slices.Clone(c.PostLogoutRedirectURIs),
		BackchannelLogoutURI:              c.BackchannelLogoutURI,
		BackchannelLogoutSessionRequired:  c.BackchannelLogoutSessionRequired,
	}
}
