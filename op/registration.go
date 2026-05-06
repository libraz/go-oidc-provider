package op

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/store"
)

// defaultIATUses is the consumption ceiling applied to an Initial
// Access Token when [RegistrationOption.IATUses] is left at zero.
// Single-use is the production-grade baseline; operators who run
// invitation flows that register multiple clients from one token raise
// this explicitly.
const defaultIATUses = 1

// iatSecretBytes is the byte length of the bearer secret returned in
// [InitialAccessTokenIssued.Value]. 256 bits matches the OAuth refresh
// token entropy used elsewhere in the library and the RFC 6819 §5.1.4.2
// recommendation.
const iatSecretBytes = 32

// iatIDBytes is the byte length of the opaque identifier persisted as
// [store.InitialAccessToken.ID]. 128 bits is sufficient for a public
// identifier (collision-resistant within any realistic IAT volume) and
// short enough to stay readable in operator logs.
const iatIDBytes = 16

// RegistrationOption configures Dynamic Client Registration (RFC 7591 /
// RFC 7592 / OpenID Connect Dynamic Client Registration 1.0). It is
// consumed by [WithDynamicRegistration] and is otherwise opaque to the
// caller.
//
// The zero value is the production-grade baseline: Initial Access
// Token required, only authorization_code + refresh_token grants, only
// the "code" response type, no metadata hook, 24 h IAT TTL, single-use
// IAT. Each field documents the override semantics individually.
type RegistrationOption struct {
	// Open, when true, allows POST /register without an Initial Access
	// Token. Production deployments SHOULD leave this false; the OP
	// emits a WARN log on every open registration and writes a
	// dcr.open_registration_used audit event so the operational impact
	// is visible.
	Open bool

	// AllowedGrantTypes whitelists the grant_type values a dynamically
	// registered client may request. Empty applies the default
	// {"authorization_code", "refresh_token"}. The "client_credentials"
	// grant is intentionally not in the default — service-to-service
	// clients are statically provisioned by design, so allowing them
	// to self-register would bypass the operator review the static
	// path enforces.
	AllowedGrantTypes []string

	// AllowedResponseTypes whitelists the response_type values a
	// dynamically registered client may request. Empty applies the
	// default {"code"}. v1.0 rejects every other value at construction
	// time; the field exists so future minor releases can broaden the
	// allowlist without breaking the option signature.
	AllowedResponseTypes []string

	// ValidateMetadata, when set, is invoked on every successful
	// RFC 7591 metadata validation pass and may reject the registration
	// with a non-nil error. The returned error is surfaced to the
	// client as "invalid_client_metadata" (RFC 7591 §3.2.2).
	// Implementations SHOULD avoid leaking internal IDs or SQL into the
	// error message; the library passes the message verbatim into
	// "error_description" subject to the library's sanitisation rules.
	ValidateMetadata func(ctx context.Context, m ClientMetadata) error

	// IATTTL is the validity window of an IAT issued via
	// [Provider.IssueInitialAccessToken]. Zero applies the default
	// (24 hours). Negative values are rejected at construction time.
	IATTTL time.Duration

	// IATUses is the maximum number of registrations a single IAT
	// admits. Zero applies the default (1, single-use). Negative
	// values are rejected at construction time.
	IATUses int

	// OpenRegistrationDefaultScopes is the scope default applied to
	// open-registration POSTs ([RegistrationOption.Open] = true) that
	// omit the scope field. The slice is space-joined into the
	// response and persisted on the [store.Client.Scopes] record so
	// the registered client can request those scopes at /authorize.
	//
	// The zero value is an empty slice — open registrations that omit
	// scope are persisted with no scopes, and any subsequent
	// /authorize request that spells out scopes the client did not
	// register for is rejected as invalid_scope. Embedders that need
	// a wider default — for example, "fall through to all public
	// scopes" — set this explicitly to {"openid"} or the discovery
	// scope list. The IAT-bound path is unchanged: when an IAT is
	// presented, [store.InitialAccessToken.AllowedScopes] still wins
	// over this option.
	//
	// Each entry MUST be a registered scope at [New] time;
	// unrecognised values are rejected as a configuration error.
	OpenRegistrationDefaultScopes []string

	// OnClientDeleted is the optional cascade hook invoked after a
	// successful DELETE /register/{client_id} (RFC 7592 §2.3). The
	// library removes the client and the registration access token
	// itself; this hook lets the embedder revoke any
	// access_token / refresh_token / session records the client
	// holds (the library cannot do this in-tree because the v1.0
	// store interfaces do not publish a "by client" enumeration).
	//
	// The hook runs in the request goroutine after the deletes
	// complete and before the 204 is written. A non-nil error is
	// logged through the configured slog handler but does not change
	// the response — the client record is already gone, and
	// surfacing the error to the RP would imply a recoverable
	// failure that the embedder cannot retry. Implementations MUST
	// be safe for concurrent use; the registration handler is
	// invoked from every request goroutine.
	OnClientDeleted func(ctx context.Context, clientID string) error
}

// ClientMetadata is the OpenID Connect Dynamic Client Registration 1.0
// §2 view of a client passed to [RegistrationOption.ValidateMetadata].
// Field semantics follow the spec; metadata fields the spec does not
// name are not visible at this hook so embedders cannot accidentally
// gate registration on internal-only attributes.
//
// Slice fields are owned by the library and MUST NOT be mutated by the
// hook; the library does not defensively copy on the way in.
type ClientMetadata struct {
	// RedirectURIs is the candidate redirect_uri set the RP submitted.
	// The library has already enforced the §J.6 native-app rules by
	// the time the hook runs; embedders MAY tighten further.
	RedirectURIs []string

	// GrantTypes is the candidate grant_types list. The library has
	// already filtered this against
	// [RegistrationOption.AllowedGrantTypes]; embedders MAY apply
	// further per-tenant restrictions.
	GrantTypes []string

	// ResponseTypes is the candidate response_types list, filtered
	// through [RegistrationOption.AllowedResponseTypes].
	ResponseTypes []string

	// Scope is the requested scope value as a single
	// space-separated string per OIDC Core 1.0 §5.4.
	Scope string

	// TokenEndpointAuthMethod is the candidate authentication method
	// at the token endpoint (e.g. "client_secret_basic",
	// "private_key_jwt", "none").
	TokenEndpointAuthMethod string

	// ApplicationType is "web" or "native"; the library forces
	// "native" for loopback / custom-scheme redirect URIs.
	ApplicationType string

	// SubjectType is "public" or "pairwise". v1.0 only accepts
	// "pairwise" when WithPairwiseSubject is configured.
	SubjectType string

	// IDTokenSignedResponseAlg is the requested ID token alg. v1.0
	// accepts ES256 only.
	IDTokenSignedResponseAlg string

	// SectorIdentifierURI is the OIDC Dynamic Client Registration 1.0
	// §2 sector identifier URL used to compute pairwise subjects.
	SectorIdentifierURI string

	// ClientName is the human-readable client name (RFC 7591 §2).
	ClientName string

	// ClientURI is the homepage URL of the client.
	ClientURI string

	// LogoURI is the URL of the client's logo.
	LogoURI string

	// PolicyURI is the URL of the client's privacy policy.
	PolicyURI string

	// TosURI is the URL of the client's terms of service.
	TosURI string

	// JWKsURI is the URL of the client's JSON Web Key Set.
	JWKsURI string

	// JWKs is the inline JSON Web Key Set, if the client supplied one
	// in lieu of jwks_uri.
	JWKs json.RawMessage

	// Contacts is the list of contact email addresses for the client.
	Contacts []string

	// DefaultMaxAge is the default max_age (seconds) the client wants
	// applied to authorize requests. Nil means the metadata was absent.
	DefaultMaxAge *int64

	// RequireAuthTime is true when the client requires the
	// "auth_time" claim in issued ID tokens.
	RequireAuthTime bool

	// DefaultACRValues lists the default acr_values for authorize
	// requests.
	DefaultACRValues []string

	// InitiateLoginURI is the URL the OP can use to initiate login at
	// the client per OIDC Core 1.0 §4.
	InitiateLoginURI string

	// RequestURIs lists the request_uri values the client pre-registers
	// for JAR (RFC 9101).
	RequestURIs []string

	// RequestObjectSigningAlg is the JWS "alg" the client commits to
	// using when it signs authorization request objects (RFC 9101 §4 /
	// OIDC Dynamic Client Registration 1.0 §2). Empty leaves the choice
	// to the OP's allow-list.
	RequestObjectSigningAlg string

	// RequestObjectEncryptionAlg, when non-empty, signals that the
	// client encrypts its authorization request objects with the
	// named JWE `alg` (OIDC Dynamic Client Registration 1.0 §2).
	// The value must be on the OP allow-list (see
	// [SupportedEncryptionAlgs]); the JAR verifier accepts any
	// allow-listed alg whose `kid` resolves through the configured
	// encryption keyset, so the registered value is recorded for the
	// metadata round-trip rather than enforced per-client.
	//
	// Stable since v0.9.1.
	RequestObjectEncryptionAlg string

	// RequestObjectEncryptionEnc mirrors [RequestObjectEncryptionAlg]
	// for the JWE content-encryption (`enc`) advertisement. Allowed
	// values are listed by [SupportedEncryptionEncs].
	//
	// Stable since v0.9.1.
	RequestObjectEncryptionEnc string

	// IDTokenEncryptedResponseAlg, when non-empty, signals that the
	// client wants the OP to encrypt issued ID tokens with the named
	// JWE `alg` (OIDC Core 1.0 §10.2 / OIDC Dynamic Client
	// Registration 1.0 §2). The value must be on the OP allow-list
	// (see [SupportedEncryptionAlgs]). The metadata is recorded for
	// the registration round-trip; outbound encryption is wired in a
	// later step.
	//
	// Stable since v0.9.1.
	IDTokenEncryptedResponseAlg string

	// IDTokenEncryptedResponseEnc mirrors [IDTokenEncryptedResponseAlg]
	// for the JWE content-encryption (`enc`) advertisement. Allowed
	// values are listed by [SupportedEncryptionEncs].
	//
	// Stable since v0.9.1.
	IDTokenEncryptedResponseEnc string

	// UserInfoEncryptedResponseAlg, when non-empty, signals that the
	// client wants the OP to encrypt /userinfo responses with the
	// named JWE `alg` (OIDC Core 1.0 §5.3 / OIDC Dynamic Client
	// Registration 1.0 §2). The value must be on the OP allow-list
	// (see [SupportedEncryptionAlgs]).
	//
	// Stable since v0.9.1.
	UserInfoEncryptedResponseAlg string

	// UserInfoEncryptedResponseEnc mirrors
	// [UserInfoEncryptedResponseAlg] for the JWE content-encryption
	// (`enc`) advertisement. Allowed values are listed by
	// [SupportedEncryptionEncs].
	//
	// Stable since v0.9.1.
	UserInfoEncryptedResponseEnc string

	// AuthorizationEncryptedResponseAlg, when non-empty, signals that
	// the client wants the OP to encrypt JARM authorization responses
	// with the named JWE `alg` (JARM / OIDC Dynamic Client
	// Registration 1.0 §2). The value must be on the OP allow-list
	// (see [SupportedEncryptionAlgs]).
	//
	// Stable since v0.9.1.
	AuthorizationEncryptedResponseAlg string

	// AuthorizationEncryptedResponseEnc mirrors
	// [AuthorizationEncryptedResponseAlg] for the JWE
	// content-encryption (`enc`) advertisement. Allowed values are
	// listed by [SupportedEncryptionEncs].
	//
	// Stable since v0.9.1.
	AuthorizationEncryptedResponseEnc string

	// IntrospectionEncryptedResponseAlg, when non-empty, signals that
	// the client wants the OP to encrypt JWT introspection responses
	// with the named JWE `alg` (RFC 7662 + draft JWT Response for
	// OAuth Token Introspection / OIDC Dynamic Client Registration
	// 1.0 §2). The value must be on the OP allow-list (see
	// [SupportedEncryptionAlgs]).
	//
	// Stable since v0.9.1.
	IntrospectionEncryptedResponseAlg string

	// IntrospectionEncryptedResponseEnc mirrors
	// [IntrospectionEncryptedResponseAlg] for the JWE
	// content-encryption (`enc`) advertisement. Allowed values are
	// listed by [SupportedEncryptionEncs].
	//
	// Stable since v0.9.1.
	IntrospectionEncryptedResponseEnc string

	// PostLogoutRedirectURIs lists the candidate URIs the client wants
	// to register for OpenID Connect RP-Initiated Logout 1.0 §3
	// post_logout_redirect_uri matching. The library has already
	// enforced the scheme/host shape (https, loopback http, or a
	// reverse-DNS custom scheme for native clients) by the time the
	// hook runs; embedders MAY tighten further (e.g. host allow-list
	// per tenant). An empty slice means the client cannot use
	// post_logout_redirect_uri at /end_session at all.
	PostLogoutRedirectURIs []string

	// BackchannelLogoutURI is the absolute https:// URL the OP POSTs
	// a logout_token to when an OIDC Back-Channel Logout 1.0 §2 event
	// fires for the registered client. Empty means the client did not
	// register for back-channel logout delivery.
	//
	// Stable since v0.9.1.
	BackchannelLogoutURI string

	// BackchannelLogoutSessionRequired requests a "sid" claim on the
	// logout_token (OIDC Back-Channel Logout 1.0 §2.5). The library
	// honours the request only when the client has a session at the
	// OP; back-channel delivery itself is independent of this flag.
	//
	// Stable since v0.9.1.
	BackchannelLogoutSessionRequired bool
}

// InitialAccessTokenSpec configures the IAT issued by
// [Provider.IssueInitialAccessToken]. Zero TTL applies the default from
// [RegistrationOption.IATTTL]; zero MaxUses applies
// [RegistrationOption.IATUses]. Negative values for either field are
// rejected.
type InitialAccessTokenSpec struct {
	// TTL is the validity window of the issued IAT. Zero falls back
	// to [RegistrationOption.IATTTL].
	TTL time.Duration

	// MaxUses is the consumption ceiling. Zero falls back to
	// [RegistrationOption.IATUses].
	MaxUses int

	// AllowedScopes constrains the scope values a client registered
	// via this IAT may request. Empty means the OP applies its global
	// scope policy without an extra IAT-level filter.
	AllowedScopes []string

	// Tag is an opaque operator-supplied identifier surfaced in audit
	// logs (e.g. "tenant-acme-2026-04"). The library writes it into
	// the IAT record verbatim and never interprets the value.
	Tag string
}

// InitialAccessTokenIssued is the result of
// [Provider.IssueInitialAccessToken]. Value is the bearer secret to
// hand to the operator; the OP retains only the SHA-256 hash. Callers
// MUST treat Value as a credential — log only ID and ExpiresAt, never
// Value. There is no second copy: the library does NOT emit Value via
// audit events, slog hooks, or any sink besides this struct, and a
// rotation flow that loses Value MUST mint a fresh IAT rather than
// attempt recovery.
//
// Recommended handling:
//
//   - Pass Value directly to the operator's secret manager (Vault,
//     AWS Secrets Manager, sealed-secret) before any error path can
//     run, so a panic / network error after the IAT row is committed
//     does not leave the secret stranded only in the calling
//     goroutine's memory.
//   - When delivering Value out of band (invitation email, RP intake
//     form), do so with the same care a one-time refresh-token rotation
//     gets: TLS-only transport, recipient identification, and the
//     understanding that the IAT itself bootstraps a confidential
//     client credential.
//   - In demos and examples Value MAY be printed to stdout for
//     observability, but the example MUST be labelled "demo only" and
//     production code MUST NOT log Value.
type InitialAccessTokenIssued struct {
	// ID is the opaque public identifier for the IAT, suitable for
	// audit logs and for [Provider.RevokeInitialAccessToken]. It is
	// not a secret.
	ID string

	// Value is the bearer secret presented at /register. It is
	// returned exactly once; the library cannot recover it after the
	// call returns. See the type-level godoc for handling guidance —
	// Value MUST NOT be logged, persisted to disk, or echoed through
	// audit emitters in production code.
	Value string

	// ExpiresAt is the wall-clock time at which the IAT becomes
	// invalid regardless of remaining uses.
	ExpiresAt time.Time
}

// WithDynamicRegistration enables RFC 7591 / RFC 7592 / OpenID Connect
// Dynamic Client Registration 1.0 on the [Provider]. The option mounts
// the /register endpoint (gated on [feature.DynamicRegistration],
// which the option enables implicitly), advertises
// "registration_endpoint" in the discovery document, and unlocks
// [Provider.IssueInitialAccessToken] /
// [Provider.RevokeInitialAccessToken].
//
// Calling the option twice fails at construction time so the operator
// notices the duplicate. The supplied [RegistrationOption] is
// validated eagerly: negative TTL or MaxUses, unknown grant types, and
// response types other than "code" are rejected. Defaults documented
// on each [RegistrationOption] field are applied at [New] time after
// every option has run.
//
// The configured [store.Store] MUST expose non-nil
// [store.InitialAccessTokenStore] and [store.RegistrationAccessTokenStore]
// substores; backends without those (a Redis-only deployment, for
// example) are rejected by [New] with a clear error rather than
// failing the first POST /register.
//
// Stable since v0.1.
func WithDynamicRegistration(o RegistrationOption) Option {
	return optionFunc(func(c *config) error {
		if c.dcr != nil {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithDynamicRegistration was supplied more than once",
			}
		}
		if err := validateRegistrationOption(o); err != nil {
			return err
		}
		// Reject a pre-existing feature flag so an embedder who passed
		// feature.DynamicRegistration through WithFeature gets a
		// deterministic error instead of silent double-enablement.
		for _, existing := range c.features {
			if existing == feature.DynamicRegistration {
				return &Error{
					Code:        codeConfiguration,
					Description: "feature.DynamicRegistration was enabled more than once",
				}
			}
		}
		// Defensive copy of slice fields so a later mutation of the
		// caller's slice does not silently change the OP's policy.
		copyCfg := o
		copyCfg.AllowedGrantTypes = slices.Clone(o.AllowedGrantTypes)
		copyCfg.AllowedResponseTypes = slices.Clone(o.AllowedResponseTypes)
		copyCfg.OpenRegistrationDefaultScopes = slices.Clone(o.OpenRegistrationDefaultScopes)
		c.dcr = &copyCfg
		// Implicitly enable the feature flag so discovery and routing
		// lookups can use the same predicate as every other feature.
		c.features = append(c.features, feature.DynamicRegistration)
		return nil
	})
}

// validateRegistrationOption enforces the [WithDynamicRegistration]
// invariants that can be checked without consulting the rest of the
// configuration. Cross-cutting checks (store substore presence,
// duplicate feature flag) live in [config.validateRegistration] /
// [WithDynamicRegistration].
func validateRegistrationOption(o RegistrationOption) error {
	if o.IATTTL < 0 {
		return &Error{
			Code:        codeConfiguration,
			Description: "WithDynamicRegistration: IATTTL must not be negative",
		}
	}
	if o.IATUses < 0 {
		return &Error{
			Code:        codeConfiguration,
			Description: "WithDynamicRegistration: IATUses must not be negative",
		}
	}
	for _, gt := range o.AllowedGrantTypes {
		if !registrationGrantAllowed(gt) {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithDynamicRegistration: AllowedGrantTypes contains unsupported value " + gt,
			}
		}
	}
	for _, rt := range o.AllowedResponseTypes {
		if rt != "code" {
			return &Error{
				Code:        codeConfiguration,
				Description: "WithDynamicRegistration: AllowedResponseTypes only accepts \"code\" in v1.0",
			}
		}
	}
	return nil
}

// registrationGrantAllowed reports whether wire is one of the
// grant.Type wire values the library is willing to expose to dynamic
// registration. The check is wire-form rather than enum-form so
// embedders can pass the same strings they already use in static
// client metadata.
func registrationGrantAllowed(wire string) bool {
	switch wire {
	case grant.AuthorizationCode.String(), grant.RefreshToken.String():
		return true
	default:
		return false
	}
}

// defaultRegistrationGrantTypes returns the wire-form grant_types a
// dynamically registered client may request when
// [RegistrationOption.AllowedGrantTypes] is left empty. The list is
// returned afresh on every call so callers may freely mutate it.
func defaultRegistrationGrantTypes() []string {
	return []string{
		grant.AuthorizationCode.String(),
		grant.RefreshToken.String(),
	}
}

// defaultRegistrationResponseTypes returns the wire-form response_types
// a dynamically registered client may request when
// [RegistrationOption.AllowedResponseTypes] is left empty. v1.0 ships
// with "code" only.
func defaultRegistrationResponseTypes() []string {
	return []string{"code"}
}

// IssueInitialAccessToken creates and persists a new Initial Access
// Token. Operators call this from Go code (cron, invitation flow,
// tenant provisioning); the library deliberately does not expose an
// admin REST endpoint for IAT issuance because authentication of the
// caller is the embedder's responsibility.
//
// The returned [InitialAccessTokenIssued.Value] is the bearer secret
// the registering RP MUST present in its POST /register
// "Authorization: Bearer …" header. The library hashes Value with
// SHA-256 before writing the row, so this call is the ONLY chance to
// read the secret — neither [Provider.RevokeInitialAccessToken] nor
// any audit emitter can recover it after the function returns. A
// caller that loses the value MUST mint a fresh IAT and revoke the
// stranded one.
//
// Treat Value with the care due any single-use credential:
//
//   - Do NOT log it. The library deliberately omits Value from audit
//     events (only ID and ExpiresAt are surfaced) so that a wired
//     audit emitter cannot inadvertently leak it; calling code MUST
//     uphold the same invariant.
//   - Pass it directly to the operator's secret manager or to the
//     out-of-band channel that delivers it to the operator (invitation
//     email, RP intake form). Hand-off SHOULD happen before any
//     subsequent error path can run.
//   - In demos and examples Value MAY be printed to stdout, but the
//     example MUST be labelled "demo only" and the same code MUST NOT
//     ship to production.
//
// Returns [ErrDynamicRegistrationDisabled] when [WithDynamicRegistration]
// was not configured. A non-nil error from the underlying store is
// returned wrapped in [*Error] with the configuration_error code so
// callers can branch on [errors.As].
func (p *Provider) IssueInitialAccessToken(ctx context.Context, spec InitialAccessTokenSpec) (*InitialAccessTokenIssued, error) {
	if p.cfg.dcr == nil {
		return nil, ErrDynamicRegistrationDisabled
	}
	if spec.TTL < 0 {
		return nil, &Error{
			Code:        codeConfiguration,
			Description: "IssueInitialAccessToken: TTL must not be negative",
		}
	}
	if spec.MaxUses < 0 {
		return nil, &Error{
			Code:        codeConfiguration,
			Description: "IssueInitialAccessToken: MaxUses must not be negative",
		}
	}
	ttl := spec.TTL
	if ttl == 0 {
		ttl = p.cfg.dcr.IATTTL
	}
	maxUses := spec.MaxUses
	if maxUses == 0 {
		maxUses = p.cfg.dcr.IATUses
	}
	id, err := newOpaqueID(iatIDBytes)
	if err != nil {
		return nil, &Error{
			Code:        codeServerError,
			Description: "IssueInitialAccessToken: random ID generation failed",
			Cause:       err,
		}
	}
	secret, err := newOpaqueID(iatSecretBytes)
	if err != nil {
		return nil, &Error{
			Code:        codeServerError,
			Description: "IssueInitialAccessToken: random secret generation failed",
			Cause:       err,
		}
	}
	now := p.cfg.clock.Now().UTC()
	rec := &store.InitialAccessToken{
		ID:            id,
		HashedValue:   hashIATSecret(secret),
		MaxUses:       maxUses,
		Uses:          0,
		AllowedScopes: slices.Clone(spec.AllowedScopes),
		Tag:           spec.Tag,
		ExpiresAt:     now.Add(ttl),
		CreatedAt:     now,
	}
	if err := p.cfg.store.InitialAccessTokens().Put(ctx, rec); err != nil {
		return nil, &Error{
			Code:        codeServerError,
			Description: "IssueInitialAccessToken: store rejected Put",
			Cause:       err,
		}
	}
	return &InitialAccessTokenIssued{
		ID:        id,
		Value:     secret,
		ExpiresAt: rec.ExpiresAt,
	}, nil
}

// RevokeInitialAccessToken deletes the IAT identified by id. The
// operation is idempotent: a missing token is reported as success
// (nil) rather than [store.ErrNotFound] because the post-condition
// the caller cares about — "the token does not exist" — is satisfied
// either way. Treating "already gone" as an error would force every
// embedder to wrap the call in [errors.Is] just to defend against
// the harmless race where two operators revoke concurrently or the
// IAT expired between lookup and revoke; we do that filtering once
// here so the surface stays clean.
//
// All other store errors are wrapped in a configuration_error
// [*Error] so callers can branch on [errors.As]. The empty id is
// rejected up front so a caller who lost track of the value cannot
// silently no-op a "delete every token" request.
//
// Returns [ErrDynamicRegistrationDisabled] when [WithDynamicRegistration]
// was not configured.
func (p *Provider) RevokeInitialAccessToken(ctx context.Context, id string) error {
	if p.cfg.dcr == nil {
		return ErrDynamicRegistrationDisabled
	}
	if id == "" {
		return &Error{
			Code:        codeConfiguration,
			Description: "RevokeInitialAccessToken: id must not be empty",
		}
	}
	if err := p.cfg.store.InitialAccessTokens().Delete(ctx, id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// Idempotent: the token is already absent, so the
			// caller's post-condition holds. Surfacing the error
			// would force every embedder to swallow it manually.
			return nil
		}
		return &Error{
			Code:        codeServerError,
			Description: "RevokeInitialAccessToken: store rejected Delete",
			Cause:       err,
		}
	}
	return nil
}

// hashIATSecret returns the lowercase hex-encoded SHA-256 digest of
// secret. The digest format matches the contract documented on
// [store.InitialAccessToken.HashedValue]; backends compare digests
// in constant time.
func hashIATSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// newOpaqueID returns a base64url (no padding) string carrying n bytes
// of cryptographically random data. The function is the single
// permitted call site for [crypto/rand.Read] inside the op package;
// existing token-issuance code paths in internal/* use the same
// pattern with their own private helper.
func newOpaqueID(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
