package registrationendpoint

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/op/store"
)

// registrationResponse is the RFC 7591 §3.2.1 response body. Optional
// fields (client_secret, registration_access_token, etc.) are tagged
// omitempty so the wire form matches the spec's "MUST/MAY" guidance.
type registrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientSecretExpiresAt   int64    `json:"client_secret_expires_at"`
	RegistrationAccessToken string   `json:"registration_access_token,omitempty"`
	RegistrationClientURI   string   `json:"registration_client_uri,omitempty"`
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	ApplicationType         string   `json:"application_type,omitempty"`
	SubjectType             string   `json:"subject_type,omitempty"`
	IDTokenAlg              string   `json:"id_token_signed_response_alg,omitempty"`
	ClientName              string   `json:"client_name,omitempty"`
	ClientURI               string   `json:"client_uri,omitempty"`
	LogoURI                 string   `json:"logo_uri,omitempty"`
	PolicyURI               string   `json:"policy_uri,omitempty"`
	TosURI                  string   `json:"tos_uri,omitempty"`
	JWKsURI                 string   `json:"jwks_uri,omitempty"`
	Contacts                []string `json:"contacts,omitempty"`
	DefaultMaxAge           int64    `json:"default_max_age,omitempty"`
	RequireAuthTime         bool     `json:"require_auth_time,omitempty"`
	DefaultACRValues        []string `json:"default_acr_values,omitempty"`
	InitiateLoginURI        string   `json:"initiate_login_uri,omitempty"`
	RequestURIs             []string `json:"request_uris,omitempty"`
	RequestObjectSigningAlg string   `json:"request_object_signing_alg,omitempty"`
}

// handleRegister implements POST /register (RFC 7591 §3). The function
// follows the 02-product-design.md §A.6.2.2 error matrix:
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
	iatScopes := iatAllowedScopes(ver)
	canonical, err := validatePolicy(
		metadata,
		deps.AllowedGrantTypes,
		deps.AllowedResponseTypes,
		iatScopes,
		deps.Scopes,
		deps.PairwiseEnabled,
	)
	if err != nil {
		writeMetadataValidationError(ctx, w, deps, err, "")
		return
	}
	if deps.ValidateMetadata != nil {
		if hookErr := deps.ValidateMetadata(ctx, canonical); hookErr != nil {
			writeMetadataValidationError(ctx, w, deps, hookErr, "")
			return
		}
	}
	if !consumeIAT(ctx, w, deps, ver) {
		return
	}
	persistRegistration(ctx, w, deps, canonical)
}

// persistRegistration mints credentials, persists the client, and
// writes the success envelope. The function is split out of
// [handleRegister] so the top-level flow stays readable; it is the
// only call site that issues client_id / client_secret / RAT.
func persistRegistration(ctx context.Context, w http.ResponseWriter, deps Deps, m ClientMetadata) {
	clientID, err := newOpaqueID(clientIDBytes)
	if err != nil {
		deps.logger().Error("dcr.client_id.generate_failed", "err", err)
		writeRegistrationError(w, http.StatusInternalServerError, codeServerError, "")
		return
	}
	confidential := isConfidentialAuthMethod(m.TokenEndpointAuthMethod)
	var rawSecret, secretHash string
	if confidential {
		rawSecret, secretHash, err = newClientSecret()
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
		ID:                       clientID,
		RedirectURIs:             slices.Clone(m.RedirectURIs),
		GrantTypes:               slices.Clone(m.GrantTypes),
		ResponseTypes:            slices.Clone(m.ResponseTypes),
		Scopes:                   splitScopes(m.Scope),
		TokenEndpointAuthMethod:  m.TokenEndpointAuthMethod,
		SecretHash:               secretHash,
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
		RequestObjectSigningAlg:  m.RequestObjectSigningAlg,
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
	deps.audit().Emit(ctx, audit.Event{
		Name:     auditDCRClientRegistered,
		Level:    audit.LevelInfo,
		Message:  "client registered via RFC 7591",
		ClientID: clientID,
	})
	writeRegistrationResponse(w, http.StatusCreated, registrationResponse{
		ClientID:                clientID,
		ClientIDIssuedAt:        now.Unix(),
		ClientSecret:            rawSecret,
		ClientSecretExpiresAt:   0,
		RegistrationAccessToken: rat,
		RegistrationClientURI:   registrationClientURI(deps.Issuer, deps.MountPrefix, deps.RegisterPath, clientID),
		RedirectURIs:            m.RedirectURIs,
		GrantTypes:              m.GrantTypes,
		ResponseTypes:           m.ResponseTypes,
		Scope:                   m.Scope,
		TokenEndpointAuthMethod: m.TokenEndpointAuthMethod,
		ApplicationType:         m.ApplicationType,
		SubjectType:             m.SubjectType,
		IDTokenAlg:              m.IDTokenSignedResponseAlg,
		ClientName:              m.ClientName,
		ClientURI:               m.ClientURI,
		LogoURI:                 m.LogoURI,
		PolicyURI:               m.PolicyURI,
		TosURI:                  m.TosURI,
		JWKsURI:                 m.JWKsURI,
		Contacts:                m.Contacts,
		DefaultMaxAge:           m.DefaultMaxAge,
		RequireAuthTime:         m.RequireAuthTime,
		DefaultACRValues:        m.DefaultACRValues,
		InitiateLoginURI:        m.InitiateLoginURI,
		RequestURIs:             m.RequestURIs,
		RequestObjectSigningAlg: m.RequestObjectSigningAlg,
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

// newClientSecret returns a freshly generated client_secret and its
// argon2id hash, ready to be stored in [store.Client.SecretHash]. The
// hash format matches the contract documented on
// [clientauth.SecretVerifier]; verification is delegated to the same
// adapter the token endpoint uses, so dynamically registered clients
// authenticate identically to statically provisioned ones.
func newClientSecret() (raw, hash string, err error) {
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

// splitScopes returns the space-separated list as a fresh slice. An
// empty input returns nil rather than an empty slice so the
// downstream JSON encoder omits the field.
func splitScopes(scope string) []string {
	if scope == "" {
		return nil
	}
	out := make([]string, 0, 4)
	start := 0
	for i := 0; i <= len(scope); i++ {
		if i == len(scope) || scope[i] == ' ' {
			if i > start {
				out = append(out, scope[start:i])
			}
			start = i + 1
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
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
