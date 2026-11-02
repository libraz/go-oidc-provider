package registrationendpoint

import (
	"bytes"
	"context"
	"log/slog"
	"net/url"
	"slices"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	internaljose "github.com/libraz/go-oidc-provider/internal/jose"
	"github.com/libraz/go-oidc-provider/internal/sector"
	"github.com/libraz/go-oidc-provider/op/store"
)

// MetadataDocumentOptions carry the OP policy [ValidateClientMetadataDocument]
// holds a fetched client ID metadata document to. The fields mirror
// [StaticClientValidationOptions]; the loopback and back-channel dev
// toggles are fixed by the validator rather than exposed.
type MetadataDocumentOptions struct {
	// AllowedGrantTypes is the OP grant_types whitelist. Empty applies
	// the library default {"authorization_code", "refresh_token"}.
	AllowedGrantTypes []string

	// AllowedResponseTypes is the OP response_types whitelist. Empty
	// applies the library default {"code"}.
	AllowedResponseTypes []string

	// AllowedClientAuthMethods is the active profile's
	// token_endpoint_auth_method whitelist. The validator intersects it
	// with {"none", "private_key_jwt"}; empty leaves that pair in force.
	AllowedClientAuthMethods []clientauth.Method

	// AllowedClientSigningAlgs is the profile's client signing alg list.
	AllowedClientSigningAlgs []internaljose.Algorithm

	// SigningAlg is the OP's issuing JWS algorithm, the only algorithm a
	// *_signed_response_alg member may name. Empty means "ES256".
	SigningAlg string

	// PairwiseEnabled admits "subject_type": "pairwise".
	PairwiseEnabled bool

	// JWEPolicy narrows the JWE alg / enc values below the allow-list.
	JWEPolicy internaljose.JWEPolicy

	// SectorResolver fetches sector_identifier_uri documents under the
	// SSRF envelope DCR uses. Nil falls back to a zero-config resolver.
	SectorResolver *sector.Resolver

	// Logger receives sector-fetch failure diagnostics. Nil installs slog.Default().
	Logger *slog.Logger
}

// metadataDocumentGrant and metadataDocumentAuthMethod bound what a
// self-asserted client may use: no shared secrets, no grants outside the
// redirect-based flow and its refresh.
func metadataDocumentGrant(g string) bool {
	return g == "authorization_code" || g == "refresh_token"
}

func metadataDocumentAuthMethod(m clientauth.Method) bool {
	return m == clientauth.MethodNone || m == clientauth.MethodPrivateKeyJWT
}

// ValidateClientMetadataDocument parses and validates a client ID
// metadata document fetched from documentURL and returns the client
// it describes, with ID set to documentURL. Parsing and the structural rules are
// the ones DCR applies to /register payloads, with the
// document-specific constraints layered on top: client_id must equal
// documentURL byte for byte, secret members are refused, the auth method is
// "none" (the default) or "private_key_jwt", grant_types are narrowed
// to the authorization-code flow, and a bad redirect_uri rejects the
// whole document. The textual "localhost" loopback host is admitted.
//
// Source, Resources and the effective Scopes are the caller's to stamp;
// the returned Scopes are the document's own request. Failures are
// [validationError] values whose code callers record.
func ValidateClientMetadataDocument(raw []byte, documentURL string, opts MetadataDocumentOptions) (*store.Client, error) {
	profile := profilePolicy{authMethods: opts.AllowedClientAuthMethods, signingAlgs: opts.AllowedClientSigningAlgs, signingAlg: opts.SigningAlg}
	m, err := parseMetadataDocument(raw, documentURL, profile.opAlg())
	if err != nil {
		return nil, err
	}
	if err := applyMetadataDocumentRules(&m, opts); err != nil {
		return nil, err
	}
	canonical, err := validatePolicy(
		m,
		m.GrantTypes,
		[]string{"code"},
		nil, // iatScopes: a document is not admitted by an IAT.
		nil, // scopes: the caller intersects with the OP's public scopes.
		opts.PairwiseEnabled,
		true,  // allowLocalhostLoopback: MCP clients register localhost alongside 127.0.0.1.
		false, // allowInsecureBackchannelLogoutForDev
		opts.JWEPolicy,
		profile,
	)
	if err != nil {
		return nil, err
	}
	// The fetch is bounded by the resolver's own timeout.
	deps := Deps{SectorResolver: opts.SectorResolver, Logger: opts.Logger}
	if err := validateSectorIdentifierURI(context.Background(), deps, canonical); err != nil {
		return nil, err
	}
	return clientFromMetadata(canonical, documentURL, ""), nil
}

// parseMetadataDocument applies the DCR parser to raw and the
// document-level checks that need the wire extras: JSON object root,
// software_statement, the client_id match, and the secret members.
func parseMetadataDocument(raw []byte, documentURL, opAlg string) (ClientMetadata, error) {
	if !bytes.HasPrefix(bytes.TrimLeft(raw, " \t\r\n"), []byte("{")) {
		return ClientMetadata{}, errInvalidClientMetadata("client metadata document must be a JSON object")
	}
	m, extras, err := parseClientMetadataWithExtras(bytes.NewReader(raw))
	if err != nil {
		return ClientMetadata{}, errInvalidClientMetadata("malformed JSON")
	}
	if extras.SoftwareStatement != "" {
		return ClientMetadata{}, &validationError{code: codeInvalidSoftwareStmt, description: "software_statement is not supported"}
	}
	if extras.ClientID != documentURL {
		return ClientMetadata{}, errInvalidClientMetadata("client_id does not match the document URL")
	}
	if len(extras.ClientSecret) != 0 || len(extras.ClientSecretExp) != 0 {
		return ClientMetadata{}, errInvalidClientMetadata("client metadata document must not carry client_secret members")
	}
	if err := validateUnpersistedMetadata(m, extras, opAlg); err != nil {
		return ClientMetadata{}, err
	}
	return m, nil
}

// applyMetadataDocumentRules narrows m to what a metadata-document
// client may use and fills the defaults that differ from DCR's.
func applyMetadataDocumentRules(m *ClientMetadata, opts MetadataDocumentOptions) error {
	if m.TokenEndpointAuthMethod == "" {
		m.TokenEndpointAuthMethod = string(clientauth.MethodNone)
	}
	method := clientauth.Method(m.TokenEndpointAuthMethod)
	if !metadataDocumentAuthMethod(method) ||
		(len(opts.AllowedClientAuthMethods) > 0 && !slices.Contains(opts.AllowedClientAuthMethods, method)) {
		return errInvalidClientMetadata("token_endpoint_auth_method " + m.TokenEndpointAuthMethod + " is not allowed for a client metadata document")
	}
	grants, err := metadataDocumentGrants(m.GrantTypes, opts.AllowedGrantTypes)
	if err != nil {
		return err
	}
	m.GrantTypes = grants
	allowedResponseTypes := opts.AllowedResponseTypes
	if len(allowedResponseTypes) == 0 {
		allowedResponseTypes = []string{"code"}
	}
	if !slices.Contains(allowedResponseTypes, "code") {
		return errInvalidClientMetadata("response_type code is not allowed")
	}
	for _, rt := range m.ResponseTypes {
		if rt != "code" {
			return errInvalidClientMetadata("response_type " + rt + " is not allowed for a client metadata document")
		}
	}
	if m.ApplicationType == "" {
		m.ApplicationType = inferMetadataDocumentApplicationType(m.RedirectURIs)
	}
	return nil
}

// metadataDocumentGrants intersects the requested grant_types (default
// authorization_code) with the document grant set and the OP allow-list.
// A document is written for every OP, so a grant this one does not
// serve is dropped rather than fatal; nothing left is a rejection.
func metadataDocumentGrants(requested, allowed []string) ([]string, error) {
	if len(requested) == 0 {
		requested = []string{"authorization_code"}
	}
	var out []string
	for _, g := range requested {
		if metadataDocumentGrant(g) && (len(allowed) == 0 || slices.Contains(allowed, g)) && !slices.Contains(out, g) {
			out = append(out, g)
		}
	}
	if len(out) == 0 {
		return nil, errInvalidClientMetadata("grant_types has no grant usable by a client metadata document")
	}
	return out, nil
}

// inferMetadataDocumentApplicationType returns native when every
// redirect_uri is a loopback http URI, so a desktop client gets the
// RFC 8252 variable-port match whatever its auth method; web otherwise.
func inferMetadataDocumentApplicationType(redirectURIs []string) string {
	if len(redirectURIs) == 0 {
		return defaultApplicationType
	}
	for _, raw := range redirectURIs {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "http" || !isLoopbackRedirectHost(u.Hostname(), true) {
			return defaultApplicationType
		}
	}
	return applicationTypeNative
}
