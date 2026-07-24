package store

import (
	"context"
	"encoding/json"
	"reflect"
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

	// ClientIDIssuedAt is the Unix timestamp (seconds) when the OP
	// issued ID. Dynamic registration stores it so RFC 7591 / RFC 7592
	// responses can round-trip the original issuance time. Static
	// clients typically leave it zero because no registration response
	// was involved.
	ClientIDIssuedAt int64

	// RedirectURIs lists the exact-match redirect_uri values the client may
	// present at the authorization endpoint. Wildcards and prefix matches
	// are forbidden: the validator compares strings byte-for-byte.
	RedirectURIs []string

	// PostLogoutRedirectURIs lists the exact-match URIs the OP will
	// redirect to from /end_session after a successful RP-Initiated
	// Logout (OIDC RP-Initiated Logout 1.0 §2). Entries are byte-for-byte
	// compared against the request's post_logout_redirect_uri parameter;
	// no wildcards or path-prefix matches. A nil or empty slice means
	// the client cannot use post_logout_redirect_uri at all and the
	// /end_session endpoint will reject any request that supplies one.
	PostLogoutRedirectURIs []string

	// BackchannelLogoutURI is the absolute https:// URL the OP POSTs a
	// Logout Token to when this client's session terminates (OpenID
	// Connect Back-Channel Logout 1.0 §2.5). An empty value disables
	// back-channel logout for this client; the library does not invent
	// a target. DCR / RM / static-client validators enforce
	// scheme=https, host required, no fragment, and no embedded
	// userinfo at registration time; the storage layer keeps the
	// field opaque so test fixtures and historical embedders that
	// wrote plaintext targets continue to load, with the deliverer's
	// SSRF gate as defence-in-depth.
	BackchannelLogoutURI string

	// BackchannelLogoutSessionRequired reports whether the OP MUST
	// include the "sid" claim in the Logout Token sent to this client
	// (OpenID Connect Back-Channel Logout 1.0 §2.4). New static and
	// dynamic registrations with true are rejected until the OP can
	// persist RP-specific session lineage. The coordinator skips a
	// legacy true row rather than leaking a browser-session SID.
	BackchannelLogoutSessionRequired bool

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

	// Resources lists the RFC 8707 resource indicator values this
	// client is allowed to request. Empty means the client has no
	// resource-indicator allowlist and requests carrying "resource"
	// are rejected. Omitting the parameter entirely remains valid and
	// leaves access-token audience selection on the OP default path.
	Resources []string

	// TokenEndpointAuthMethod is the client authentication method used at
	// the token endpoint, encoded with the values defined in OpenID
	// Connect Core 1.0 §9 (for example "client_secret_basic",
	// "private_key_jwt", "tls_client_auth", "none").
	TokenEndpointAuthMethod string

	// TokenEndpointAuthSigningAlg restricts the JWS "alg" a
	// private_key_jwt client may use for client_assertion signatures
	// (OIDC Dynamic Client Registration 1.0 §2). Empty means "any OP
	// supported assertion alg"; non-empty values are compared
	// byte-for-byte against the protected header.
	TokenEndpointAuthSigningAlg string

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
	// max_age (OIDC Dynamic Client Registration 1.0 §2). Nil means
	// the client did not register the metadata; a non-nil pointer to
	// zero preserves the spec's "force fresh authentication" meaning.
	DefaultMaxAge *int64

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

	// RequestObjectEncryptionAlg signals to the OP that the client
	// intends to encrypt its authorization request objects (OIDC
	// Dynamic Client Registration 1.0 §2). The value is the JWE `alg`
	// the client uses; the OP advertises the field in DCR responses
	// and discovery's request_object_encryption_alg_values_supported
	// so RPs can detect which algorithms are honoured.
	//
	// The library does not enforce a per-client pin: the JAR verifier
	// accepts any JWE whose protected header carries an `alg` from
	// the OP allow-list and whose `kid` resolves through the
	// configured encryption keyset. The field is recorded so the OP
	// metadata round-trips faithfully and so a future hardening pass
	// can tighten the alg check without a wire-shape change.
	RequestObjectEncryptionAlg string

	// RequestObjectEncryptionEnc mirrors [RequestObjectEncryptionAlg]
	// for the JWE content-encryption (`enc`) advertisement. Empty
	// means "no preference" — the OP still validates the inbound
	// `enc` against the v0.9.1 allow-list (`A128GCM` / `A256GCM`).
	RequestObjectEncryptionEnc string

	// IDTokenEncryptedResponseAlg signals that the client wants
	// issued ID tokens encrypted with the named JWE `alg` (OIDC Core
	// 1.0 §10.2 / OIDC Dynamic Client Registration 1.0 §2). Empty
	// means "no encryption" — the OP issues a plain signed ID token.
	// The value is recorded for the metadata round-trip; outbound
	// encryption is wired in a later step.
	IDTokenEncryptedResponseAlg string

	// IDTokenEncryptedResponseEnc mirrors
	// [IDTokenEncryptedResponseAlg] for the JWE content-encryption
	// (`enc`) advertisement. Empty means "no preference"; the OP
	// applies its v0.9.1 allow-list (`A128GCM` / `A256GCM`).
	IDTokenEncryptedResponseEnc string

	// UserInfoEncryptedResponseAlg signals that the client wants
	// /userinfo responses encrypted with the named JWE `alg` (OIDC
	// Core 1.0 §5.3 / OIDC Dynamic Client Registration 1.0 §2).
	// Empty means "plain JSON or signed JWT" — the OP does not
	// encrypt the response.
	UserInfoEncryptedResponseAlg string

	// UserInfoEncryptedResponseEnc mirrors
	// [UserInfoEncryptedResponseAlg] for the JWE content-encryption
	// (`enc`) advertisement.
	UserInfoEncryptedResponseEnc string

	// AuthorizationEncryptedResponseAlg signals that the client wants
	// JARM authorization responses encrypted with the named JWE `alg`
	// (JARM / OIDC Dynamic Client Registration 1.0 §2). Empty means
	// the OP returns a signed-only JARM response (or, when JARM is not
	// in effect, plain query/fragment parameters).
	AuthorizationEncryptedResponseAlg string

	// AuthorizationEncryptedResponseEnc mirrors
	// [AuthorizationEncryptedResponseAlg] for the JWE
	// content-encryption (`enc`) advertisement.
	AuthorizationEncryptedResponseEnc string

	// IntrospectionEncryptedResponseAlg signals that the client wants
	// JWT introspection responses encrypted with the named JWE `alg`
	// (RFC 7662 + draft JWT Response for OAuth Token Introspection /
	// OIDC Dynamic Client Registration 1.0 §2). Empty means the OP
	// returns the introspection result as plain JSON or as a signed
	// JWT according to [IntrospectionSignedResponseAlg].
	IntrospectionEncryptedResponseAlg string

	// IntrospectionEncryptedResponseEnc mirrors
	// [IntrospectionEncryptedResponseAlg] for the JWE
	// content-encryption (`enc`) advertisement.
	IntrospectionEncryptedResponseEnc string
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

// StaticClientReconciler is the atomic write capability required by
// op.WithStaticClients. It is separate from [ClientRegistry] because dynamic
// registration writes one client per request, while provider construction
// must reconcile an entire configured set without exposing a partial seed
// when one record conflicts or the backend fails.
//
// ReconcileStaticClients MUST apply the complete clients slice atomically:
//
//   - a missing ID is inserted;
//   - an existing record equivalent under [StaticClientEquivalent] is a
//     successful no-op;
//   - an existing record with different metadata or a non-static Source MUST
//     return [ErrConflict];
//   - any other error MUST leave every client record exactly as it was before
//     the call.
//
// The operation does not delete stored static clients absent from clients.
// Embedders rotate metadata or secrets and remove retired clients through
// their explicit administration path before changing the startup seed.
// Backends normally implement this contract with a database transaction or
// by staging a complete in-memory snapshot and publishing it under one lock.
type StaticClientReconciler interface {
	ClientStore

	ReconcileStaticClients(ctx context.Context, clients []*Client) error
}

// StaticClientEquivalent reports whether two static-client records carry the
// same persisted configuration. It treats nil and empty slices identically
// because SQL adapters commonly decode an empty JSON array where an in-memory
// seed used nil, and it treats the legacy empty Source as
// [ClientSourceStatic]. SecretHash remains part of the comparison; op.New
// verifies the configured plaintext against an existing hash and reuses that
// hash before calling a reconciler.
func StaticClientEquivalent(a, b *Client) bool {
	if a == nil || b == nil {
		return a == b
	}
	left := normalizedStaticClient(*a)
	right := normalizedStaticClient(*b)
	return reflect.DeepEqual(left, right)
}

func normalizedStaticClient(client Client) Client {
	client.RedirectURIs = nilIfEmpty(client.RedirectURIs)
	client.PostLogoutRedirectURIs = nilIfEmpty(client.PostLogoutRedirectURIs)
	client.GrantTypes = nilIfEmpty(client.GrantTypes)
	client.ResponseTypes = nilIfEmpty(client.ResponseTypes)
	client.Scopes = nilIfEmpty(client.Scopes)
	client.Resources = nilIfEmpty(client.Resources)
	client.Contacts = nilIfEmpty(client.Contacts)
	client.DefaultACRValues = nilIfEmpty(client.DefaultACRValues)
	client.RequestURIs = nilIfEmpty(client.RequestURIs)
	if len(client.JWKs) == 0 {
		client.JWKs = nil
	}
	if client.Source == "" {
		client.Source = ClientSourceStatic
	}
	return client
}

func nilIfEmpty[T any](values []T) []T {
	if len(values) == 0 {
		return nil
	}
	return values
}
