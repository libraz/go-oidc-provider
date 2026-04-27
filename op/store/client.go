package store

import (
	"context"
	"encoding/json"
)

// ClientSource identifies how the client record reached the OP. The library
// uses it to gate behaviours that are only valid for statically-provisioned
// clients (for example the FirstParty auto-consent path documented in
// plans/002-product-design.md §A.6) and to differentiate audit events that
// would otherwise look identical (RFC 7591 self-registration vs. an
// embedder-built admin UI calling [ClientRegistry] directly).
//
// Backends store the value verbatim. An empty string ("") is treated as the
// legacy / unset case; for backwards compatibility with records persisted
// before this discriminator existed, the library treats "" identically to
// [ClientSourceStatic]. New writers SHOULD set the field explicitly.
type ClientSource string

const (
	// ClientSourceStatic marks clients injected via op.WithStaticClients
	// at provider construction. Most embedders use this exclusively.
	ClientSourceStatic ClientSource = "static"

	// ClientSourceDynamic marks clients self-registered via the RFC
	// 7591 endpoint. They may not opt into FirstParty auto-consent and
	// may delete themselves via RFC 7592.
	ClientSourceDynamic ClientSource = "dynamic"

	// ClientSourceAdmin marks clients created by the embedder's own
	// admin UI calling [ClientRegistry] directly (out-of-band). The
	// library treats them identically to [ClientSourceStatic] for the
	// purposes of auto-consent gating; the discriminator exists so audit
	// log analysis can tell them apart.
	ClientSourceAdmin ClientSource = "admin"
)

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

	// Source records how this client record was created (see
	// [ClientSource]). The library reads it to gate behaviour that is
	// only valid for statically-provisioned clients (for example
	// FirstParty auto-consent). An empty string is treated as
	// [ClientSourceStatic] so records persisted before this field
	// existed continue to work unchanged.
	Source ClientSource

	// ApplicationType mirrors OpenID Connect Dynamic Client Registration
	// 1.0 §2 application_type. The library does not branch on the value
	// in v1.0; it is stored so RFC 7592 GET / PUT can echo the metadata
	// the client originally registered.
	ApplicationType string

	// SubjectType records the OIDC subject_type the client requested at
	// registration ("public" or "pairwise"). The library consults it
	// when minting subject identifiers for ID tokens; statically-
	// provisioned clients leave the field empty to inherit the OP
	// default.
	SubjectType string

	// IDTokenSignedResponseAlg records the JWS alg the client expects
	// for ID tokens. v1.0 enforces ES256-only at registration time, so
	// the field is informational; later versions may relax the policy.
	IDTokenSignedResponseAlg string

	// IntrospectionSignedResponseAlg records the JWS alg the client expects
	// when receiving JWT-formatted introspection responses (RFC 9701 §7).
	// When non-empty the OP MUST emit a JWT response regardless of the
	// request's Accept header. v1.0 only supports "ES256"; non-empty
	// values that do not equal "ES256" are stored verbatim but the
	// introspection handler treats them as "always JWT" — algorithm
	// enforcement lands when the project supports more than one signing
	// alg.
	IntrospectionSignedResponseAlg string

	// SectorIdentifierURI is the optional pairwise sector identifier
	// from OIDC Core §5. The library does not fetch it eagerly; it is
	// stored verbatim so the eventual pairwise computation can resolve
	// the sector without a second backend round-trip.
	SectorIdentifierURI string

	// ClientName is the OIDC profile display name (RFC 7591 §2). The
	// library never renders it itself — UI is the embedder's job — but
	// it is persisted so the management endpoint round-trips the value.
	ClientName string

	// ClientURI is the homepage URL of the client (RFC 7591 §2).
	ClientURI string

	// LogoURI is a URL pointing to the client's logo (RFC 7591 §2). The
	// library does not validate the host or fetch the asset.
	LogoURI string

	// PolicyURI is a URL pointing to the client's privacy policy
	// (RFC 7591 §2).
	PolicyURI string

	// TosURI is a URL pointing to the client's terms of service
	// (RFC 7591 §2).
	TosURI string

	// JWKsURI is the URL the OP fetches to obtain the client's public
	// keys for private_key_jwt / request_object verification
	// (OIDC Dynamic Client Registration 1.0 §2). It is mutually
	// exclusive with JWKs.
	JWKsURI string

	// JWKs is the inline JWK Set the client supplies when it cannot
	// host a public JWKS URL (OIDC Dynamic Client Registration 1.0 §2).
	// The library stores the raw bytes; consumers parse them into the
	// internal JOSE representation lazily.
	JWKs json.RawMessage

	// Contacts is a list of operator-meaningful identifiers (typically
	// email addresses) the OP can use to contact the client owner
	// (RFC 7591 §2).
	Contacts []string

	// DefaultMaxAge requests the OP enforce a maximum authentication
	// age (in seconds) for this client, even when the request omits
	// max_age (OIDC Dynamic Client Registration 1.0 §2).
	DefaultMaxAge int64

	// RequireAuthTime requests the OP include the auth_time claim in
	// every ID token issued to this client (OIDC Dynamic Client
	// Registration 1.0 §2).
	RequireAuthTime bool

	// DefaultACRValues lists the acr_values the OP assumes when the
	// authorization request omits the parameter (OIDC Dynamic Client
	// Registration 1.0 §2).
	DefaultACRValues []string

	// InitiateLoginURI is the URL a third party can hit to start an
	// SSO flow toward this client (OIDC Dynamic Client Registration
	// 1.0 §2). The library does not invoke it; it is stored for the
	// embedder's use.
	InitiateLoginURI string

	// RequestURIs is the optional preregistered set of request_uri
	// values the client may reference in authorization requests
	// (OIDC Dynamic Client Registration 1.0 §2).
	RequestURIs []string

	// RequestObjectSigningAlg restricts the JWS "alg" the client may
	// use when signing authorization request objects (RFC 9101 §4 /
	// OIDC Dynamic Client Registration 1.0 §2). Empty means "any alg
	// the OP allows for request objects." When non-empty the verifier
	// rejects request objects whose header alg does not match.
	RequestObjectSigningAlg string
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
