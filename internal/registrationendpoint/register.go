package registrationendpoint

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/clone"
	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/internal/oidcscope"
	"github.com/libraz/go-oidc-provider/op/store"
)

// registrationResponse is the RFC 7591 §3.2.1 response body. Optional
// fields (client_secret, registration_access_token, etc.) are tagged
// omitempty so the wire form matches the spec's "MUST/MAY" guidance.
type registrationResponse struct {
	ClientID                          string          `json:"client_id"`
	ClientIDIssuedAt                  int64           `json:"client_id_issued_at"`
	ClientSecret                      string          `json:"client_secret,omitempty"`
	ClientSecretExpiresAt             int64           `json:"client_secret_expires_at"`
	RegistrationAccessToken           string          `json:"registration_access_token,omitempty"`
	RegistrationClientURI             string          `json:"registration_client_uri,omitempty"`
	RedirectURIs                      []string        `json:"redirect_uris,omitempty"`
	GrantTypes                        []string        `json:"grant_types,omitempty"`
	ResponseTypes                     []string        `json:"response_types,omitempty"`
	Scope                             string          `json:"scope,omitempty"`
	TokenEndpointAuthMethod           string          `json:"token_endpoint_auth_method,omitempty"`
	TokenEndpointAuthSigningAlg       string          `json:"token_endpoint_auth_signing_alg,omitempty"`
	ApplicationType                   string          `json:"application_type,omitempty"`
	SubjectType                       string          `json:"subject_type,omitempty"`
	IDTokenAlg                        string          `json:"id_token_signed_response_alg,omitempty"`
	SectorIdentifierURI               string          `json:"sector_identifier_uri,omitempty"`
	ClientName                        string          `json:"client_name,omitempty"`
	ClientURI                         string          `json:"client_uri,omitempty"`
	LogoURI                           string          `json:"logo_uri,omitempty"`
	PolicyURI                         string          `json:"policy_uri,omitempty"`
	TosURI                            string          `json:"tos_uri,omitempty"`
	JWKsURI                           string          `json:"jwks_uri,omitempty"`
	JWKs                              json.RawMessage `json:"jwks,omitempty"`
	Contacts                          []string        `json:"contacts,omitempty"`
	DefaultMaxAge                     *int64          `json:"default_max_age,omitempty"`
	RequireAuthTime                   bool            `json:"require_auth_time,omitempty"`
	DefaultACRValues                  []string        `json:"default_acr_values,omitempty"`
	InitiateLoginURI                  string          `json:"initiate_login_uri,omitempty"`
	RequestURIs                       []string        `json:"request_uris,omitempty"`
	RequestObjectSigningAlg           string          `json:"request_object_signing_alg,omitempty"`
	RequestObjectEncryptionAlg        string          `json:"request_object_encryption_alg,omitempty"`
	RequestObjectEncryptionEnc        string          `json:"request_object_encryption_enc,omitempty"`
	IDTokenEncryptedResponseAlg       string          `json:"id_token_encrypted_response_alg,omitempty"`
	IDTokenEncryptedResponseEnc       string          `json:"id_token_encrypted_response_enc,omitempty"`
	UserInfoEncryptedResponseAlg      string          `json:"userinfo_encrypted_response_alg,omitempty"`
	UserInfoEncryptedResponseEnc      string          `json:"userinfo_encrypted_response_enc,omitempty"`
	AuthorizationEncryptedResponseAlg string          `json:"authorization_encrypted_response_alg,omitempty"`
	AuthorizationEncryptedResponseEnc string          `json:"authorization_encrypted_response_enc,omitempty"`
	IntrospectionEncryptedResponseAlg string          `json:"introspection_encrypted_response_alg,omitempty"`
	IntrospectionEncryptedResponseEnc string          `json:"introspection_encrypted_response_enc,omitempty"`
	PostLogoutRedirectURIs            []string        `json:"post_logout_redirect_uris,omitempty"`
	BackchannelLogoutURI              string          `json:"backchannel_logout_uri,omitempty"`
	BackchannelLogoutSessionRequired  bool            `json:"backchannel_logout_session_required,omitempty"`
}

// handleRegister implements POST /register (RFC 7591 §3). The function
// runs its failure checks in a fixed order so an unauthenticated
// caller never reaches metadata parsing or persistence:
// IAT verification first, then content-type / body parse, then
// metadata validation, then secret / RAT generation, then persistence.
// Decomposing the body keeps cyclop's max-complexity gate happy while
// the readable flow lives in this top-level function.
func handleRegister(w http.ResponseWriter, r *http.Request, deps Deps) {
	ctx := r.Context()
	ver, ok := verifyIAT(ctx, w, r, deps)
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
	if err := validateUnpersistedMetadata(extras); err != nil {
		writeMetadataValidationError(ctx, w, deps, err, "")
		return
	}
	iatScopes := iatAllowedScopes(ver)
	canonical, err := validatePolicy(
		metadata,
		deps.AllowedGrantTypes,
		deps.AllowedResponseTypes,
		iatScopes,
		ver.Open,
		deps.OpenRegistrationDefaultScopes,
		deps.Scopes,
		deps.PairwiseEnabled,
		deps.AllowLocalhostLoopback,
		deps.AllowInsecureBackchannelLogoutForDev,
		deps.JWEPolicy,
	)
	if err != nil {
		writeMetadataValidationError(ctx, w, deps, err, "")
		return
	}
	if err := validateSectorIdentifierURI(ctx, deps, canonical); err != nil {
		writeMetadataValidationError(ctx, w, deps, err, "")
		return
	}
	if deps.ValidateMetadata != nil {
		if hookErr := deps.ValidateMetadata(ctx, canonical); hookErr != nil {
			writeMetadataValidationError(ctx, w, deps, hookErr, "")
			return
		}
	}
	persistRegistration(ctx, w, deps, canonical, ver)
}

// persistRegistration mints credentials, persists the client, and
// writes the success envelope. The function is split out of
// [handleRegister] so the top-level flow stays readable; it is the
// only call site that issues client_id / client_secret / RAT.
//
// The IAT increment is performed last, after every credential
// generation and persistence step succeeds, so a transient entropy
// or store fault never consumes a one-time IAT without producing a
// client. The remaining race window — IAT-consume succeeds for a
// second concurrent caller while we are still mid-flight — is
// bounded by rolling back both the client and RAT on the
// [store.ErrConflict] branch of consumeIAT. The recovery path is
// best-effort: a double failure surfaces a 500 to the caller and an
// audit log entry the operator reconciles by dropping the orphan
// client / RAT pair.
func persistRegistration(ctx context.Context, w http.ResponseWriter, deps Deps, m ClientMetadata, ver iatVerification) {
	clientID, err := newOpaqueID(clientIDBytes)
	if err != nil {
		deps.logger().Error("dcr.client_id.generate_failed", "err", err)
		writeRegistrationError(w, http.StatusInternalServerError, codeServerError, "")
		return
	}
	confidential := isConfidentialAuthMethod(m.TokenEndpointAuthMethod)
	publicClient := isPublicAuthMethod(m.TokenEndpointAuthMethod)
	var rawSecret, secretHash string
	if confidential {
		rawSecret, secretHash, err = newClientSecret(deps.HighEntropyClientSecrets)
		if err != nil {
			deps.logger().Error("dcr.client_secret.generate_failed", "err", err)
			writeRegistrationError(w, http.StatusInternalServerError, codeServerError, "")
			return
		}
	}
	rat, err := newOpaqueID(ratBytes)
	if err != nil {
		deps.logger().Error("dcr.rat.generate_failed", "err", err)
		writeRegistrationError(w, http.StatusInternalServerError, codeServerError, "")
		return
	}
	now := deps.now().UTC()
	client := &store.Client{
		ID:                                clientID,
		ClientIDIssuedAt:                  now.Unix(),
		RedirectURIs:                      slices.Clone(m.RedirectURIs),
		GrantTypes:                        slices.Clone(m.GrantTypes),
		ResponseTypes:                     slices.Clone(m.ResponseTypes),
		Scopes:                            oidcscope.Parse(m.Scope),
		TokenEndpointAuthMethod:           m.TokenEndpointAuthMethod,
		TokenEndpointAuthSigningAlg:       m.TokenEndpointAuthSigningAlg,
		SecretHash:                        secretHash,
		PublicClient:                      publicClient,
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
	if err := deps.Clients.RegisterClient(ctx, client); err != nil {
		deps.logger().Error("dcr.client.register_failed", "err", err, "client_id", clientID)
		writeRegistrationError(w, http.StatusInternalServerError, codeServerError, "")
		return
	}
	ratRec := &store.RegistrationAccessToken{
		ClientID:    clientID,
		HashedValue: hashSecret(rat),
		CreatedAt:   now,
	}
	if err := deps.RegistrationAccessTokens.Put(ctx, ratRec); err != nil {
		deps.logger().Error("dcr.rat.put_failed", "err", err, "client_id", clientID)
		// Best-effort rollback of the client record so a partial
		// state does not leak into the registry. Errors here are
		// logged but not surfaced to the caller; the original 500
		// is the source of truth.
		if delErr := deps.Clients.DeleteClient(ctx, clientID); delErr != nil {
			deps.logger().Error("dcr.client.rollback_failed", "err", delErr, "client_id", clientID)
		}
		writeRegistrationError(w, http.StatusInternalServerError, codeServerError, "")
		return
	}
	// IAT consumption fires last, after the client and RAT have
	// been persisted, so an upstream entropy / store failure cannot
	// burn the IAT without producing a client. The remaining loss
	// window is the IAT-race after a successful registration: the
	// second concurrent caller sees [store.ErrConflict] in
	// IncrementUses; we roll back both the client and the RAT so
	// the wire 500 matches a no-op store state.
	if !consumeIAT(ctx, w, deps, ver) {
		if delErr := deps.RegistrationAccessTokens.Delete(ctx, clientID); delErr != nil {
			deps.logger().Error("dcr.rat.iat_rollback_failed", "err", delErr, "client_id", clientID)
		}
		if delErr := deps.Clients.DeleteClient(ctx, clientID); delErr != nil {
			deps.logger().Error("dcr.client.iat_rollback_failed", "err", delErr, "client_id", clientID)
		}
		return
	}
	deps.audit().Emit(ctx, audit.Event{
		Name:     auditDCRClientRegistered,
		Level:    audit.LevelInfo,
		Message:  "client registered via RFC 7591",
		ClientID: clientID,
	})
	writeRegistrationResponse(w, http.StatusCreated, registrationResponse{
		ClientID:                          clientID,
		ClientIDIssuedAt:                  client.ClientIDIssuedAt,
		ClientSecret:                      rawSecret,
		ClientSecretExpiresAt:             0,
		RegistrationAccessToken:           rat,
		RegistrationClientURI:             registrationClientURI(deps.Issuer, deps.MountPrefix, deps.RegisterPath, clientID),
		RedirectURIs:                      m.RedirectURIs,
		GrantTypes:                        m.GrantTypes,
		ResponseTypes:                     m.ResponseTypes,
		Scope:                             m.Scope,
		TokenEndpointAuthMethod:           m.TokenEndpointAuthMethod,
		TokenEndpointAuthSigningAlg:       m.TokenEndpointAuthSigningAlg,
		ApplicationType:                   m.ApplicationType,
		SubjectType:                       m.SubjectType,
		IDTokenAlg:                        m.IDTokenSignedResponseAlg,
		SectorIdentifierURI:               m.SectorIdentifierURI,
		ClientName:                        m.ClientName,
		ClientURI:                         m.ClientURI,
		LogoURI:                           m.LogoURI,
		PolicyURI:                         m.PolicyURI,
		TosURI:                            m.TosURI,
		JWKsURI:                           m.JWKsURI,
		JWKs:                              append(json.RawMessage(nil), m.JWKs...),
		Contacts:                          m.Contacts,
		DefaultMaxAge:                     clone.Int64Ptr(m.DefaultMaxAge),
		RequireAuthTime:                   m.RequireAuthTime,
		DefaultACRValues:                  m.DefaultACRValues,
		InitiateLoginURI:                  m.InitiateLoginURI,
		RequestURIs:                       m.RequestURIs,
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
		PostLogoutRedirectURIs:            m.PostLogoutRedirectURIs,
		BackchannelLogoutURI:              m.BackchannelLogoutURI,
		BackchannelLogoutSessionRequired:  m.BackchannelLogoutSessionRequired,
	})
}

// iatAllowedScopes returns the IAT-bound scope allowlist or nil when
// the request was admitted on the open-registration path. Centralising
// the access keeps the handler from sprinkling nil-checks against
// [iatVerification.Token] across the code path.
func iatAllowedScopes(ver iatVerification) []string {
	if ver.Open || ver.Token == nil {
		return nil
	}
	return ver.Token.AllowedScopes
}

// isConfidentialAuthMethod reports whether the requested
// token_endpoint_auth_method requires a server-issued client_secret.
// "private_key_jwt" and "none" are excluded: the former uses an RP-
// supplied keypair (the OP never sees a secret), and the latter is
// the public-client posture.
func isConfidentialAuthMethod(m string) bool {
	switch m {
	case "client_secret_basic", "client_secret_post":
		return true
	default:
		return false
	}
}

// isPublicAuthMethod reports whether the requested
// token_endpoint_auth_method designates the public-client posture.
// Only "none" qualifies; private_key_jwt clients are confidential
// (they hold an RP-issued private key the OP never sees), so
// [store.Client.PublicClient] must be false for them or
// [clientauth.methodAllowedForClient] would block the
// assertion verifier path.
func isPublicAuthMethod(m string) bool {
	return m == "none"
}

// newClientSecret returns a freshly generated client_secret and its
// stored encoding, ready for [store.Client.SecretHash]. Verification
// is delegated to the same adapter the token endpoint uses, so
// dynamically registered clients authenticate identically to
// statically provisioned ones.
//
// highEntropy selects the encoding, and must track the OP-wide
// setting rather than being decided here. Both branches mint 256 bits
// from crypto/rand, so the secret is beyond guessing either way and
// the keyed hash is sound for it; what the OP-wide setting fixes is
// the cost of the timing shim that stands in for a failed
// verification, and a registration minting the format the shim is not
// sized for would make its own clients distinguishable from
// unregistered ones.
func newClientSecret(highEntropy bool) (raw, hash string, err error) {
	if highEntropy {
		return clientauth.NewHighEntropySecret()
	}
	raw, err = newOpaqueID(clientSecretBytes)
	if err != nil {
		return "", "", err
	}
	hasher := &clientauth.Argon2id{}
	hash, err = hasher.Hash(raw)
	if err != nil {
		return "", "", err
	}
	return raw, hash, nil
}

// writeRegistrationResponse marshals body and writes it with the
// cache-control and content-type headers RFC 7591 §3.2.1 requires.
// The status is 201 for new registrations and 200 for management
// reads; the caller passes the value.
func writeRegistrationResponse(w http.ResponseWriter, status int, body registrationResponse) {
	stampNoStore(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	// Encoding a fixed-shape struct never fails at runtime; an error
	// here would be a programmer bug. The response carries
	// credentials, but they were minted for delivery to this client
	// over TLS, which is the documented purpose of the response.
	_ = json.NewEncoder(w).Encode(body) //nolint:gosec // RFC 7591 §3.2.1 mandates the field names.
}

// writeMetadataValidationError translates a structural [validationError]
// or a [Deps.ValidateMetadata] hook error into the wire envelope. The
// auditEventClientID parameter is the resolved client_id for management
// flows (PUT) or "" on POST registration; it surfaces in the audit
// trail so operators can correlate validation failures with specific
// clients.
func writeMetadataValidationError(
	ctx context.Context,
	w http.ResponseWriter,
	deps Deps,
	err error,
	auditEventClientID string,
) {
	deps.audit().Emit(ctx, audit.Event{
		Name:     auditDCRMetadataValidation,
		Level:    audit.LevelInfo,
		Message:  "metadata validation failed",
		ClientID: auditEventClientID,
	})
	if ve, ok := asValidationError(err); ok {
		writeRegistrationError(w, http.StatusBadRequest, ve.code, ve.description)
		return
	}
	// Hook-supplied error: sanitise the message before exposing it.
	desc := sanitizeDescription(err.Error())
	writeRegistrationError(w, http.StatusBadRequest, codeInvalidClientMetadata, desc)
}
