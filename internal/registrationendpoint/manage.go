package registrationendpoint

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/backchannel"
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
	client, _, ok := verifyRAT(ctx, w, r, deps, clientID)
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
// the same validators, rotates the RAT (RFC 7592 leaves rotation
// undefined; this OP issues a fresh registration_access_token on every
// successful update and revokes the previous one), and updates the
// client.
//
// An update grants no scope the client did not name. The registration
// path's defaults exist to give a new client an initial authority; an
// already-registered client that omits the scope member is asking for
// the member to be deleted (RFC 7592 §2.2), so its scopes are cleared
// rather than replaced with whatever default a fresh registration would
// have received.
func handleUpdate(w http.ResponseWriter, r *http.Request, deps Deps, clientID string) {
	ctx := r.Context()
	existing, rat, ok := verifyRAT(ctx, w, r, deps, clientID)
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
	if err := validateUnpersistedMetadata(metadata, extras); err != nil {
		writeMetadataValidationError(ctx, w, deps, err, clientID)
		return
	}
	canonical, err := validatePolicy(
		metadata,
		deps.AllowedGrantTypes,
		deps.AllowedResponseTypes,
		ratAllowedScopes(rat), // immutable IAT ceiling; empty legacy RAT means unrestricted.
		deps.Scopes,
		deps.PairwiseEnabled,
		deps.AllowLocalhostLoopback,
		deps.AllowInsecureBackchannelLogoutForDev,
		deps.JWEPolicy,
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
	rotated, ok := rotateAndUpdate(ctx, w, deps, existing, canonical, ratAllowedScopes(rat))
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

// rotatedRegistration carries the outcome of a successful update: the
// persisted client plus the freshly minted credentials the caller
// includes in the response body.
type rotatedRegistration struct {
	client    *store.Client
	rawRAT    string
	rawSecret string
}

// rotateAndUpdate is the persistence path for PUT
// /register/{client_id}. It mints a fresh RAT, persists the updated
// client, and overwrites the RAT row, carrying allowedScopes onto the
// rotated token so the ceiling an operator bound to the original
// initial access token survives every rotation.
func rotateAndUpdate(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	existing *store.Client,
	m ClientMetadata,
	allowedScopes []string,
) (rotatedRegistration, bool) {
	rawRAT, err := newOpaqueID(ratBytes)
	if err != nil {
		deps.logger().Error("dcr.rat.generate_failed", "err", err, "client_id", existing.ID)
		writeRegistrationError(w, http.StatusInternalServerError, codeServerError, "")
		return rotatedRegistration{}, false
	}
	confidential := isConfidentialAuthMethod(m.TokenEndpointAuthMethod)
	rawSecret, secretHash, err := secretMaterialForUpdate(existing, confidential, deps.HighEntropyClientSecrets)
	if err != nil {
		deps.logger().Error("dcr.client_secret.generate_failed", "err", err, "client_id", existing.ID)
		writeRegistrationError(w, http.StatusInternalServerError, codeServerError, "")
		return rotatedRegistration{}, false
	}
	updated := applyMetadataToClient(existing, m, secretHash)
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
		ClientID:      existing.ID,
		HashedValue:   hashSecret(rawRAT),
		AllowedScopes: slices.Clone(allowedScopes),
		CreatedAt:     now,
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

// applyMetadataToClient returns the record PUT /register/{client_id}
// persists: a copy of the stored client with every field the RFC 7591
// §2 metadata document can express overwritten from the submitted
// values (an omitted member clears the field, per RFC 7592 §2.2).
//
// Copying first is load-bearing. [store.Client] carries persisted
// configuration the registration wire shape has no member for — the
// RFC 8707 resource-indicator allow-list — plus the identity and
// provenance the OP assigned at creation. Rebuilding the record from the
// metadata alone would silently discard all of it the first time the RP
// submits an update, so an operator's out-of-band configuration would
// survive exactly until the client next edited its own display name.
//
// The fields that deliberately do not come from the metadata are:
//
//   - ID / ClientIDIssuedAt are immutable identity the OP minted.
//   - Source records how the record reached the registry, which is a
//     property of its creation rather than of any later edit. Only a
//     self-registered record reaches this path at all ([verifyRAT]
//     refuses every other origin), so the copied value is the same one
//     a restamp would write.
//   - SecretHash comes from [secretMaterialForUpdate], which decides
//     whether the auth-method change requires minting, clearing, or
//     preserving the secret.
func applyMetadataToClient(existing *store.Client, m ClientMetadata, secretHash string) *store.Client {
	updated := *existing
	// introspection_signed_response_alg is persisted client metadata. RFC
	// 7592 §2.2 treats an omitted member as a request to clear it, just like
	// the other metadata fields below; do not carry an operator's old value
	// through a client-authenticated PUT that omits the member.
	updated.IntrospectionSignedResponseAlg = normalizeIntrospectionSignedResponseAlg(m.IntrospectionSignedResponseAlg)
	updated.RedirectURIs = slices.Clone(m.RedirectURIs)
	updated.GrantTypes = slices.Clone(m.GrantTypes)
	updated.ResponseTypes = slices.Clone(m.ResponseTypes)
	updated.Scopes = oidcscope.Parse(m.Scope)
	updated.TokenEndpointAuthMethod = m.TokenEndpointAuthMethod
	updated.TokenEndpointAuthSigningAlg = m.TokenEndpointAuthSigningAlg
	updated.SecretHash = secretHash
	updated.PublicClient = isPublicAuthMethod(m.TokenEndpointAuthMethod)
	updated.ApplicationType = m.ApplicationType
	updated.SubjectType = m.SubjectType
	updated.IDTokenSignedResponseAlg = m.IDTokenSignedResponseAlg
	updated.SectorIdentifierURI = m.SectorIdentifierURI
	updated.ClientName = m.ClientName
	updated.ClientURI = m.ClientURI
	updated.LogoURI = m.LogoURI
	updated.PolicyURI = m.PolicyURI
	updated.TosURI = m.TosURI
	updated.JWKsURI = m.JWKsURI
	updated.JWKs = append(json.RawMessage(nil), m.JWKs...)
	updated.Contacts = slices.Clone(m.Contacts)
	updated.DefaultMaxAge = clone.Int64Ptr(m.DefaultMaxAge)
	updated.RequireAuthTime = m.RequireAuthTime
	updated.DefaultACRValues = slices.Clone(m.DefaultACRValues)
	updated.InitiateLoginURI = m.InitiateLoginURI
	updated.RequestURIs = slices.Clone(m.RequestURIs)
	updated.RequestObjectSigningAlg = m.RequestObjectSigningAlg
	updated.RequestObjectEncryptionAlg = m.RequestObjectEncryptionAlg
	updated.RequestObjectEncryptionEnc = m.RequestObjectEncryptionEnc
	updated.IDTokenEncryptedResponseAlg = m.IDTokenEncryptedResponseAlg
	updated.IDTokenEncryptedResponseEnc = m.IDTokenEncryptedResponseEnc
	updated.UserInfoEncryptedResponseAlg = m.UserInfoEncryptedResponseAlg
	updated.UserInfoEncryptedResponseEnc = m.UserInfoEncryptedResponseEnc
	updated.AuthorizationEncryptedResponseAlg = m.AuthorizationEncryptedResponseAlg
	updated.AuthorizationEncryptedResponseEnc = m.AuthorizationEncryptedResponseEnc
	updated.IntrospectionEncryptedResponseAlg = m.IntrospectionEncryptedResponseAlg
	updated.IntrospectionEncryptedResponseEnc = m.IntrospectionEncryptedResponseEnc
	updated.PostLogoutRedirectURIs = slices.Clone(m.PostLogoutRedirectURIs)
	updated.BackchannelLogoutURI = m.BackchannelLogoutURI
	updated.BackchannelLogoutSessionRequired = m.BackchannelLogoutSessionRequired
	return &updated
}

// ratAllowedScopes projects the immutable scope ceiling from a verified RAT.
// A nil RAT is treated as unrestricted defensively; the verifier only returns
// nil on failure, and callers invoke this helper after checking ok.
func ratAllowedScopes(rat *store.RegistrationAccessToken) []string {
	if rat == nil || len(rat.AllowedScopes) == 0 {
		return nil
	}
	return slices.Clone(rat.AllowedScopes)
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
func secretMaterialForUpdate(existing *store.Client, confidential, highEntropy bool) (raw, hash string, err error) {
	if !confidential {
		return "", "", nil
	}
	if existing == nil {
		return "", "", errors.New("registrationendpoint: existing client is required for secret update")
	}
	if existing.SecretHash == "" {
		raw, hash, err := newClientSecret(highEntropy)
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
// that maintain those indexes wire the cascade through the hook, whose
// contract is to revoke every access_token / refresh_token / session
// the deleted client holds and to deliver Back-Channel Logout.
//
//nolint:gocognit // Delete ordering and each non-rollbackable cascade outcome are intentionally explicit.
func handleDelete(w http.ResponseWriter, r *http.Request, deps Deps, clientID string) {
	ctx := r.Context()
	client, _, ok := verifyRAT(ctx, w, r, deps, clientID)
	if !ok {
		return
	}
	snapshotClient, snapshotSubjects := snapshotDeletedClient(ctx, deps, client)
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
	if snapshotClient != nil {
		if deps.Backchannel != nil {
			if _, err := deps.Backchannel.NotifyClientDeleted(ctx, backchannel.ClientDeletionSnapshot{
				Client:   snapshotClient,
				Subjects: snapshotSubjects,
			}); err != nil {
				deps.logger().Error("dcr.client.backchannel_delete_failed", "err", err, "client_id", clientID)
			}
		}
		if deps.OnClientDeletedSnapshot != nil {
			if err := deps.OnClientDeletedSnapshot(ctx, snapshotClient, slices.Clone(snapshotSubjects)); err != nil {
				deps.logger().Error("dcr.client.snapshot_cascade_failed", "err", err, "client_id", clientID)
			}
		}
	}
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

func snapshotDeletedClient(ctx context.Context, deps Deps, client *store.Client) (*store.Client, []string) {
	if client == nil || deps.GrantSubjects == nil {
		return nil, nil
	}
	snapshot := cloneClientForDeletion(client)
	page, err := deps.GrantSubjects.ListSubjectsByClient(ctx, client.ID, "", deps.MaxDeleteSubjects)
	if err != nil {
		deps.logger().Error("dcr.client.subject_snapshot_failed", "err", err, "client_id", client.ID)
		return nil, nil
	}
	if page.NextCursor != "" {
		deps.logger().Warn("dcr.client.subject_snapshot_bounded", "client_id", client.ID, "limit", deps.MaxDeleteSubjects)
	}
	if len(page.Subjects) > deps.MaxDeleteSubjects {
		page.Subjects = page.Subjects[:deps.MaxDeleteSubjects]
	}
	return snapshot, slices.Clone(page.Subjects)
}

func cloneClientForDeletion(client *store.Client) *store.Client {
	snapshot := *client
	snapshot.RedirectURIs = slices.Clone(client.RedirectURIs)
	snapshot.PostLogoutRedirectURIs = slices.Clone(client.PostLogoutRedirectURIs)
	snapshot.GrantTypes = slices.Clone(client.GrantTypes)
	snapshot.ResponseTypes = slices.Clone(client.ResponseTypes)
	snapshot.Scopes = slices.Clone(client.Scopes)
	snapshot.Resources = slices.Clone(client.Resources)
	snapshot.Contacts = slices.Clone(client.Contacts)
	snapshot.DefaultACRValues = slices.Clone(client.DefaultACRValues)
	snapshot.RequestURIs = slices.Clone(client.RequestURIs)
	snapshot.JWKs = append(json.RawMessage(nil), client.JWKs...)
	if client.DefaultMaxAge != nil {
		value := *client.DefaultMaxAge
		snapshot.DefaultMaxAge = &value
	}
	return &snapshot
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
		IntrospectionSignedResponseAlg:    normalizeIntrospectionSignedResponseAlg(c.IntrospectionSignedResponseAlg),
		PostLogoutRedirectURIs:            slices.Clone(c.PostLogoutRedirectURIs),
		BackchannelLogoutURI:              c.BackchannelLogoutURI,
		BackchannelLogoutSessionRequired:  c.BackchannelLogoutSessionRequired,
	}
}
