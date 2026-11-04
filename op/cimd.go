package op

import "context"

// ClientIDMetadataDocuments configures OAuth Client ID Metadata Document
// support: a client presents an HTTPS URL as its client_id and the OP
// fetches the JSON metadata document at that URL to resolve the client.
// Registered (static or dynamic) clients always take precedence over a
// URL of the same value.
//
// Experimental: tracks an IETF draft, so the surface MAY change in a
// minor release on a wire-incompatible draft bump.
type ClientIDMetadataDocuments struct {
	// Allow, when non-nil, is consulted with the client_id URL on every
	// resolution, cache hits included, before any fetch. Returning false
	// treats the client as unknown. nil admits every URL that passes the
	// draft's URL rules.
	//
	// Experimental: tracks an IETF draft, so the field MAY change in a
	// minor release on a wire-incompatible draft bump.
	Allow func(ctx context.Context, clientID string) bool
}

// WithClientIDMetadataDocuments enables client ID metadata documents
// (draft-ietf-oauth-client-id-metadata-document), the registration path
// MCP authorization clients use. It is off by default. Documents may
// declare only the authorization_code and refresh_token grants and the
// none or private_key_jwt authentication methods; PKCE is always
// required for these clients and they never receive first-party
// auto-consent. Discovery advertises client_id_metadata_document_supported.
//
// The option may be supplied at most once; a repeat fails [New].
//
// Experimental: tracks an IETF draft, so the surface MAY change in a
// minor release on a wire-incompatible draft bump.
func WithClientIDMetadataDocuments(c ClientIDMetadataDocuments) Option {
	return optionFunc(func(cfg *config) error {
		if err := cfg.claimOnce("WithClientIDMetadataDocuments"); err != nil {
			return err
		}
		cfg.cimd = &c
		return nil
	})
}
