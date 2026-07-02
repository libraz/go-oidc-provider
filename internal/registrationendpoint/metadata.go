package registrationendpoint

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/libraz/go-oidc-provider/internal/clone"
)

// ClientMetadata is the internal-package mirror of op.ClientMetadata.
// internal/* must not import op/, so the type is declared
// here and the op layer converts between the two through a thin shim.
// Field documentation lives on the public op.ClientMetadata; this type
// intentionally carries the same shape so the conversion remains a
// field-for-field copy.
type ClientMetadata struct {
	RedirectURIs                      []string
	GrantTypes                        []string
	ResponseTypes                     []string
	Scope                             string
	TokenEndpointAuthMethod           string
	TokenEndpointAuthSigningAlg       string
	ApplicationType                   string
	SubjectType                       string
	IDTokenSignedResponseAlg          string
	SectorIdentifierURI               string
	ClientName                        string
	ClientURI                         string
	LogoURI                           string
	PolicyURI                         string
	TosURI                            string
	JWKsURI                           string
	JWKs                              json.RawMessage
	Contacts                          []string
	DefaultMaxAge                     *int64
	RequireAuthTime                   bool
	DefaultACRValues                  []string
	InitiateLoginURI                  string
	RequestURIs                       []string
	RequestObjectSigningAlg           string
	RequestObjectEncryptionAlg        string
	RequestObjectEncryptionEnc        string
	IDTokenEncryptedResponseAlg       string
	IDTokenEncryptedResponseEnc       string
	UserInfoEncryptedResponseAlg      string
	UserInfoEncryptedResponseEnc      string
	AuthorizationEncryptedResponseAlg string
	AuthorizationEncryptedResponseEnc string
	IntrospectionEncryptedResponseAlg string
	IntrospectionEncryptedResponseEnc string
	PostLogoutRedirectURIs            []string
	BackchannelLogoutURI              string
	BackchannelLogoutSessionRequired  bool
}

// metadataWire is the JSON shape RFC 7591 §2 / OIDC Dynamic Client
// Registration 1.0 §2 expect on the wire. The struct is unexported
// because callers consume the parsed [ClientMetadata] only; the wire
// shape is an implementation detail.
type metadataWire struct {
	RedirectURIs                      []string        `json:"redirect_uris,omitempty"`
	GrantTypes                        []string        `json:"grant_types,omitempty"`
	ResponseTypes                     []string        `json:"response_types,omitempty"`
	Scope                             string          `json:"scope,omitempty"`
	TokenEndpointAuthMethod           string          `json:"token_endpoint_auth_method,omitempty"`
	TokenEndpointAuthSigningAlg       string          `json:"token_endpoint_auth_signing_alg,omitempty"`
	ApplicationType                   string          `json:"application_type,omitempty"`
	SubjectType                       string          `json:"subject_type,omitempty"`
	IDTokenSignedResponseAlg          string          `json:"id_token_signed_response_alg,omitempty"`
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

	// Standard metadata the library does not persist or enforce today.
	// RFC 7591 §2 requires authorization servers to ignore metadata
	// they do not understand; parse-and-drop keeps DisallowUnknownFields
	// useful for truly misspelled local fields without rejecting common
	// interoperable registrations.
	SoftwareID                                 string   `json:"software_id,omitempty"`
	SoftwareVersion                            string   `json:"software_version,omitempty"`
	TLSClientCertificateBoundAccessTokens      *bool    `json:"tls_client_certificate_bound_access_tokens,omitempty"`
	BackchannelTokenDeliveryMode               string   `json:"backchannel_token_delivery_mode,omitempty"`
	BackchannelClientNotificationEndpoint      string   `json:"backchannel_client_notification_endpoint,omitempty"`
	BackchannelAuthenticationRequestSigningAlg string   `json:"backchannel_authentication_request_signing_alg,omitempty"`
	BackchannelUserCodeParameter               *bool    `json:"backchannel_user_code_parameter,omitempty"`
	AuthorizationSignedResponseAlg             string   `json:"authorization_signed_response_alg,omitempty"`
	AuthorizationDetailsTypes                  []string `json:"authorization_details_types,omitempty"`

	// SoftwareStatement is parsed only so the handler can detect its
	// presence and reject with invalid_software_statement; v1.0 does
	// not implement RFC 7591 §3.1.1 software statement verification.
	SoftwareStatement string `json:"software_statement,omitempty"`

	// ClientID is parsed solely so the handler can detect that the
	// caller tried to mutate the immutable identifier (RFC 7592 §2.2);
	// the value is otherwise ignored.
	ClientID string `json:"client_id,omitempty"`

	// RFC 7592 reserved response fields. The PUT path MUST reject
	// requests that try to write these values back.
	ClientSecret            json.RawMessage `json:"client_secret,omitempty"`
	ClientSecretExpiresAt   json.RawMessage `json:"client_secret_expires_at,omitempty"`
	ClientIDIssuedAt        json.RawMessage `json:"client_id_issued_at,omitempty"`
	RegistrationAccessToken json.RawMessage `json:"registration_access_token,omitempty"`
	RegistrationClientURI   json.RawMessage `json:"registration_client_uri,omitempty"`
}

// metadataExtras carries the wire fields that are not part of the
// [ClientMetadata] surface but the validator still needs to inspect.
// Returned alongside [ClientMetadata] only when the caller wants to
// reject software_statement or detect a client_id override; the POST
// path uses this to fail with invalid_software_statement, the PUT path
// uses it to enforce immutability.
type metadataExtras struct {
	SoftwareStatement string
	ClientID          string
	ClientSecret      json.RawMessage
	ClientSecretExp   json.RawMessage
	ClientIDIssuedAt  json.RawMessage
	RegAccessToken    json.RawMessage
	RegClientURI      json.RawMessage
}

// parseClientMetadataWithExtras is the variant the handler uses; it
// returns both the public-shape metadata and the wire extras (software
// statement, attempted client_id) so the call site can reject those
// before running the structural validator.
func parseClientMetadataWithExtras(r io.Reader) (ClientMetadata, metadataExtras, error) {
	var w metadataWire
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&w); err != nil {
		return ClientMetadata{}, metadataExtras{}, fmt.Errorf("registrationendpoint: decode metadata: %w", err)
	}
	// Reject any trailing JSON document. Multiple objects in one
	// body is a parser-confusion vector — a reverse proxy / WAF /
	// audit sink that scans the full body sees a different shape
	// than the OP consumed. Mirrors [httpx.DecodeJSON]'s `dec.More()`
	// policy; DCR predates the shared helper so the check is
	// duplicated rather than imported.
	if dec.More() {
		return ClientMetadata{}, metadataExtras{}, errors.New("registrationendpoint: decode metadata: trailing JSON document")
	}
	m := ClientMetadata{
		RedirectURIs:                      cloneStrings(w.RedirectURIs),
		GrantTypes:                        cloneStrings(w.GrantTypes),
		ResponseTypes:                     cloneStrings(w.ResponseTypes),
		Scope:                             w.Scope,
		TokenEndpointAuthMethod:           w.TokenEndpointAuthMethod,
		TokenEndpointAuthSigningAlg:       w.TokenEndpointAuthSigningAlg,
		ApplicationType:                   w.ApplicationType,
		SubjectType:                       w.SubjectType,
		IDTokenSignedResponseAlg:          w.IDTokenSignedResponseAlg,
		SectorIdentifierURI:               w.SectorIdentifierURI,
		ClientName:                        w.ClientName,
		ClientURI:                         w.ClientURI,
		LogoURI:                           w.LogoURI,
		PolicyURI:                         w.PolicyURI,
		TosURI:                            w.TosURI,
		JWKsURI:                           w.JWKsURI,
		JWKs:                              append(json.RawMessage(nil), w.JWKs...),
		Contacts:                          cloneStrings(w.Contacts),
		DefaultMaxAge:                     clone.Int64Ptr(w.DefaultMaxAge),
		RequireAuthTime:                   w.RequireAuthTime,
		DefaultACRValues:                  cloneStrings(w.DefaultACRValues),
		InitiateLoginURI:                  w.InitiateLoginURI,
		RequestURIs:                       cloneStrings(w.RequestURIs),
		RequestObjectSigningAlg:           w.RequestObjectSigningAlg,
		RequestObjectEncryptionAlg:        w.RequestObjectEncryptionAlg,
		RequestObjectEncryptionEnc:        w.RequestObjectEncryptionEnc,
		IDTokenEncryptedResponseAlg:       w.IDTokenEncryptedResponseAlg,
		IDTokenEncryptedResponseEnc:       w.IDTokenEncryptedResponseEnc,
		UserInfoEncryptedResponseAlg:      w.UserInfoEncryptedResponseAlg,
		UserInfoEncryptedResponseEnc:      w.UserInfoEncryptedResponseEnc,
		AuthorizationEncryptedResponseAlg: w.AuthorizationEncryptedResponseAlg,
		AuthorizationEncryptedResponseEnc: w.AuthorizationEncryptedResponseEnc,
		IntrospectionEncryptedResponseAlg: w.IntrospectionEncryptedResponseAlg,
		IntrospectionEncryptedResponseEnc: w.IntrospectionEncryptedResponseEnc,
		PostLogoutRedirectURIs:            cloneStrings(w.PostLogoutRedirectURIs),
		BackchannelLogoutURI:              w.BackchannelLogoutURI,
		BackchannelLogoutSessionRequired:  w.BackchannelLogoutSessionRequired,
	}
	extras := metadataExtras{
		SoftwareStatement: w.SoftwareStatement,
		ClientID:          w.ClientID,
		ClientSecret:      append(json.RawMessage(nil), w.ClientSecret...),
		ClientSecretExp:   append(json.RawMessage(nil), w.ClientSecretExpiresAt...),
		ClientIDIssuedAt:  append(json.RawMessage(nil), w.ClientIDIssuedAt...),
		RegAccessToken:    append(json.RawMessage(nil), w.RegistrationAccessToken...),
		RegClientURI:      append(json.RawMessage(nil), w.RegistrationClientURI...),
	}
	return m, extras, nil
}

// cloneStrings returns a fresh copy of in so a later mutation of the
// caller's slice cannot retroactively change the parsed value. nil
// inputs return nil.
func cloneStrings(in []string) []string {
	if in == nil {
		return nil
	}
	return slices.Clone(in)
}

// Library defaults for the OIDC profile fields when the caller leaves
// them blank. The values mirror 02-product-design.md
// §A.6.2 / §K.3.
const (
	defaultAuthMethod      = "client_secret_basic"
	defaultSubjectType     = "public"
	defaultIDTokenAlg      = "ES256"
	defaultApplicationType = "web"
	applicationTypeNative  = "native"
)
