package store

import "context"

// Client is the persistent representation of a registered OAuth 2.0 / OpenID
// Connect client (RFC 6749 §2, OpenID Connect Dynamic Client Registration 1.0
// §2). The struct is intentionally a plain data carrier: the storage layer
// returns it verbatim, and the library performs every policy decision
// (redirect-URI matching, grant negotiation, secret verification) in
// validating code paths that consume it.
//
// All slice fields are treated as read-only by the library; backends MUST
// either return a fresh slice on every call or guarantee that the returned
// slice is never mutated by their own code.
type Client struct {
	// ID is the OAuth client_id. It MUST be globally unique within the OP
	// and stable across the lifetime of the client; rotating ID requires a
	// re-registration.
	ID string

	// RedirectURIs lists the exact-match redirect_uri values the client may
	// present at the authorization endpoint. Wildcards and prefix matches
	// are forbidden: the validator compares strings byte-for-byte.
	RedirectURIs []string

	// GrantTypes lists the grant_type values the client is permitted to use
	// at the token endpoint (for example "authorization_code",
	// "refresh_token", "client_credentials"). Empty means the client may
	// not call the token endpoint.
	GrantTypes []string

	// ResponseTypes lists the response_type values the client may request
	// at the authorization endpoint (for example "code", "code id_token").
	ResponseTypes []string

	// Scopes lists the scopes the client is registered to request. The
	// library intersects this list with the request and the resource
	// server's policy when issuing tokens.
	Scopes []string

	// TokenEndpointAuthMethod is the client authentication method used at
	// the token endpoint, encoded with the values defined in OpenID
	// Connect Core 1.0 §9 (for example "client_secret_basic",
	// "private_key_jwt", "tls_client_auth", "none").
	TokenEndpointAuthMethod string

	// SecretHash is the salted hash of the client_secret for clients that
	// authenticate with a shared secret. Backends MUST NOT store the raw
	// secret; the library never writes one back. The value is opaque to
	// the library, which delegates verification to a hash adapter.
	SecretHash string

	// PublicClient marks clients that cannot keep a secret (single-page
	// apps, native apps). Public clients may not use confidential auth
	// methods and MUST use PKCE on the authorization_code flow.
	PublicClient bool
}

// ClientStore is the read-only contract every OP backend MUST satisfy.
// It is deliberately the smallest possible interface so that callers who
// register clients externally (provisioning service, IaC) need not
// implement write methods at all.
type ClientStore interface {
	// GetClient returns the client identified by id. It MUST return
	// [ErrNotFound] when no such client exists; any other non-nil error
	// indicates a transport or backend fault.
	GetClient(ctx context.Context, id string) (*Client, error)
}

// ClientRegistry extends [ClientStore] with the write-side capabilities used
// by OAuth 2.0 Dynamic Client Registration (RFC 7591) and the management
// endpoints of OpenID Connect Dynamic Client Registration 1.0. Backends that
// do not support DCR need not implement this interface; the library detects
// support via a runtime type assertion.
type ClientRegistry interface {
	ClientStore

	// RegisterClient persists a new client. It MUST return
	// [ErrAlreadyExists] if a client with the same ID is already stored;
	// the library uses that signal to surface a clean RFC 7591 §3.2.2
	// error response.
	RegisterClient(ctx context.Context, c *Client) error

	// UpdateClient replaces the stored representation of c.ID with c. It
	// MUST return [ErrNotFound] if no client with that ID exists. Backends
	// that implement optimistic concurrency MAY return [ErrConflict].
	UpdateClient(ctx context.Context, c *Client) error

	// DeleteClient removes the client identified by id. It MUST return
	// [ErrNotFound] if no such client exists so that callers can
	// distinguish a no-op delete from a successful one.
	DeleteClient(ctx context.Context, id string) error
}
