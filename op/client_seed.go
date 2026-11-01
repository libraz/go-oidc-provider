package op

import (
	"slices"
	"strconv"
	"time"

	"github.com/libraz/go-oidc-provider/internal/clone"
	"github.com/libraz/go-oidc-provider/op/grant"
	"github.com/libraz/go-oidc-provider/op/store"
)

// checkDefaultMaxAge rejects a negative DefaultMaxAge; nil (unset) and
// zero (always re-authenticate) are both valid.
func checkDefaultMaxAge(kind, id string, maxAge *int64) error {
	if maxAge != nil && *maxAge < 0 {
		return newConfigurationError(kind+" "+id+": DefaultMaxAge must not be negative, got "+
			strconv.FormatInt(*maxAge, 10), nil)
	}
	return nil
}

// ClientSeed is the unexported-method interface every typed client
// builder satisfies. The single method [ClientSeed.seed] projects the
// builder onto the canonical [store.Client] record the OP persists.
// Embedders never implement this interface themselves: the library
// ships three concrete builders ([PublicClient], [ConfidentialClient],
// [PrivateKeyJWTClient]) that cover every static-client posture the
// option layer admits today.
// The unexported method is deliberate: it locks the surface to the
// shipped builders so an embedder cannot accidentally bypass the
// Source: ClientSourceStatic invariant by constructing a custom
// ClientSeed that returns a [store.Client] with a different source.
// Embedders who need full control can still call
// [store.ClientRegistry.RegisterClient] themselves; this seam is for
// the common static-client path.
type ClientSeed interface {
	seed() (store.Client, error)
}

// defaultGrantTypes() returns the wire-form grant_types every typed
// builder defaults to when [PublicClient.GrantTypes] et al. are left
// empty. The list (authorization_code + refresh_token) matches the
// canonical OIDC code-flow shape and is returned afresh on every
// call so callers may freely mutate it.
func defaultGrantTypes() []string {
	return []string{grant.AuthorizationCode.String(), grant.RefreshToken.String()}
}

// defaultResponseTypes() returns the wire-form response_types every
// typed builder defaults to when [PublicClient.ResponseTypes] et al.
// are left empty. v1.0 ships with "code" only; the helper returns a
// fresh slice so callers may freely mutate it.
func defaultResponseTypes() []string {
	return []string{"code"}
}

// seedGrantAndResponseTypes returns copies of grants and responses, each
// replaced by its builder default when empty.
func seedGrantAndResponseTypes(grants, responses []string) (grantTypes, responseTypes []string) {
	if len(grants) == 0 {
		grantTypes = defaultGrantTypes()
	} else {
		grantTypes = slices.Clone(grants)
	}
	if len(responses) == 0 {
		responseTypes = defaultResponseTypes()
	} else {
		responseTypes = slices.Clone(responses)
	}
	return grantTypes, responseTypes
}

// PublicClient is the typed builder for a client that cannot keep a
// secret (single-page apps, native apps). The seed sets
// PublicClient: true, Source: ClientSourceStatic, and
// TokenEndpointAuthMethod: "none"; PKCE compensates for the lack of
// confidential authentication.
// Hand to [WithStaticClients] to register at construction time:
//
//	op.WithStaticClients(
//	    op.PublicClient{
//	        ID:           "demo-spa",
//	        RedirectURIs: []string{"https://app.example.com/callback"},
//	        Scopes:       []string{"openid", "profile"},
//	    },
//	)
type PublicClient struct {
	// ID is the OAuth client_id. MUST be unique within the OP.
	ID string

	// RedirectURIs lists the exact-match redirect_uri values the
	// client may present at /authorize. Wildcards are forbidden;
	// the validator compares strings byte-for-byte.
	RedirectURIs []string

	// Scopes lists the scopes the client is registered to request.
	// The library intersects this list with the request and the
	// scope catalogue at runtime.
	Scopes []string

	// Resources lists the RFC 8707 resource indicators the client is
	// allowed to request. Empty means resource-indicator requests are
	// rejected for this client, while requests omitting the parameter
	// remain valid.
	Resources []string

	// GrantTypes overrides the default
	// {"authorization_code", "refresh_token"}. Empty applies the
	// default; non-empty replaces it entirely.
	GrantTypes []string

	// ResponseTypes overrides the default {"code"}. Empty applies
	// the default; non-empty replaces it entirely.
	ResponseTypes []string

	// PostLogoutRedirectURIs lists the exact-match URIs the OP
	// accepts in OIDC RP-Initiated Logout 1.0 §2's
	// post_logout_redirect_uri parameter. Embedders that omit this
	// field cannot use the redirect-after-logout shape; the OP still
	// renders the static "Signed out" page on /end_session.
	PostLogoutRedirectURIs []string

	// BackchannelLogoutURI is the absolute https:// URL the OP POSTs
	// a Logout Token to when this client's session terminates (OIDC
	// Back-Channel Logout 1.0). An empty value opts the client out
	// of fan-out; the registry-side wiring already short-circuits on
	// the empty path so the wire never sees a malformed delivery.
	BackchannelLogoutURI string

	// BackchannelLogoutSessionRequired requests a "sid" claim on the
	// Logout Token (OIDC Back-Channel Logout 1.0 §2.4). The provider
	// currently rejects true because it cannot recover an RP-specific
	// session lineage; sub-only back-channel logout remains available.
	BackchannelLogoutSessionRequired bool

	// ApplicationType mirrors OIDC Dynamic Client Registration 1.0's
	// "application_type" metadata. Typical values are "native" and
	// "web". The library does not enforce a specific value but
	// surfaces it through discovery / introspection so embedders can
	// drive their own routing on it.
	ApplicationType string

	// SubjectType requests a particular OIDC subject_type ("public"
	// or "pairwise"). When the provider is constructed with
	// [WithPairwiseSubject], clients whose SubjectType is "pairwise"
	// receive pairwise subjects; "public" or empty preserve public
	// subjects. Without [WithPairwiseSubject], "pairwise" is rejected
	// by static-client validation.
	SubjectType string

	// DefaultMaxAge is the maximum authentication age, in seconds, the
	// OP enforces for this client when the request omits max_age. Nil
	// leaves it unset. A pointer to zero means every request
	// re-authenticates the user. A negative value is rejected by
	// [WithStaticClients].
	//
	// Stable since v1.5.
	DefaultMaxAge *int64

	// RequireAuthTime makes the OP include auth_time in every ID token
	// issued to this client.
	//
	// Stable since v1.5.
	RequireAuthTime bool

	// DefaultACRValues lists the acr values the OP assumes, in order of
	// preference, when the request omits acr_values. Empty leaves it
	// unset. Every entry must be listed in [WithACRValuesSupported]
	// when that option is set and, under the built-in ACR policies,
	// resolvable by it; [New] rejects the configuration otherwise.
	//
	// Stable since v1.5.
	DefaultACRValues []string
}

// seed projects c onto a [store.Client] with the public-client
// invariants (PublicClient: true, auth method "none", Source
// ClientSourceStatic) applied. The returned record is owned by the
// caller; subsequent mutation does not affect c.
func (c PublicClient) seed() (store.Client, error) {
	if err := checkDefaultMaxAge("PublicClient", c.ID, c.DefaultMaxAge); err != nil {
		return store.Client{}, err
	}
	grants, responses := seedGrantAndResponseTypes(c.GrantTypes, c.ResponseTypes)
	return store.Client{
		ID:                               c.ID,
		RedirectURIs:                     slices.Clone(c.RedirectURIs),
		Scopes:                           slices.Clone(c.Scopes),
		Resources:                        slices.Clone(c.Resources),
		GrantTypes:                       grants,
		ResponseTypes:                    responses,
		TokenEndpointAuthMethod:          AuthNone.String(),
		PublicClient:                     true,
		Source:                           store.ClientSourceStatic,
		PostLogoutRedirectURIs:           slices.Clone(c.PostLogoutRedirectURIs),
		BackchannelLogoutURI:             c.BackchannelLogoutURI,
		BackchannelLogoutSessionRequired: c.BackchannelLogoutSessionRequired,
		ApplicationType:                  c.ApplicationType,
		SubjectType:                      c.SubjectType,
		DefaultMaxAge:                    clone.Int64Ptr(c.DefaultMaxAge),
		RequireAuthTime:                  c.RequireAuthTime,
		DefaultACRValues:                 slices.Clone(c.DefaultACRValues),
	}, nil
}

// ConfidentialClient is the typed builder for a client that
// authenticates with a shared secret. The seed hashes Secret through
// [HashClientSecret] (argon2id with the library's defaults) before
// assembling the [store.Client] record; the plaintext leaves only as
// the hash field.
// AuthMethod selects the credential transport:
// [AuthClientSecretBasic] (the default) or [AuthClientSecretPost].
// Other [AuthMethod] values are accepted by the type but the
// downstream wiring will treat them as unknown for credential
// negotiation.
//
//	op.WithStaticClients(
//	    op.ConfidentialClient{
//	        ID:           "demo-confidential",
//	        Secret:       "demo-secret",
//	        AuthMethod:   op.AuthClientSecretBasic,
//	        RedirectURIs: []string{"https://app.example.com/callback"},
//	        Scopes:       []string{"openid", "profile"},
//	    },
//	)
type ConfidentialClient struct {
	// ID is the OAuth client_id. MUST be unique within the OP.
	ID string

	// Secret is the plaintext client_secret. The seed hashes it
	// through [HashClientSecret]; the library never persists the
	// raw value.
	//
	// Mutually exclusive with SecretHash.
	Secret string

	// SecretHash is a stored encoding the caller produced itself,
	// through [NewClientSecret] or [HashHighEntropyClientSecret]. The
	// seed writes it verbatim, so the plaintext never enters the
	// configuration at all.
	//
	// This is the required form under
	// [WithHighEntropyClientSecrets]: Secret hashes with Argon2id,
	// which that option refuses, and the refusal is deliberate — a
	// secret handed to the library as plaintext is one somebody typed
	// or pasted, which is the case the fast verifier is not safe for.
	//
	// Mutually exclusive with Secret.
	SecretHash string

	// PreviousSecret is the plaintext of the secret this client used
	// before its latest rotation. The OP keeps accepting it until
	// PreviousSecretExpiresAt, so callers can switch over without an
	// outage. It is hashed with Argon2id, or, when it still verifies
	// against the stored record, the stored hash is reused so repeated
	// runs of [SyncStaticClients] stay unchanged.
	//
	// Mutually exclusive with PreviousSecretHash. Requires
	// PreviousSecretExpiresAt.
	//
	// Stable since v1.5.
	PreviousSecret string

	// PreviousSecretHash is the stored encoding of the previous secret,
	// produced through [NewClientSecret] or [HashHighEntropyClientSecret].
	// It is the required form under [WithHighEntropyClientSecrets].
	//
	// Mutually exclusive with PreviousSecret. Requires
	// PreviousSecretExpiresAt.
	//
	// Stable since v1.5.
	PreviousSecretHash string

	// PreviousSecretExpiresAt is the instant after which the previous
	// secret stops authenticating. It is required whenever PreviousSecret
	// or PreviousSecretHash is set. An instant already in the past is
	// accepted; the previous secret is then simply ignored.
	//
	// Stable since v1.5.
	PreviousSecretExpiresAt time.Time

	// AuthMethod selects the token-endpoint authentication method.
	// Empty defaults to [AuthClientSecretBasic].
	AuthMethod AuthMethod

	// RedirectURIs lists the exact-match redirect_uri values the
	// client may present at /authorize.
	RedirectURIs []string

	// Scopes lists the scopes the client is registered to request.
	Scopes []string

	// Resources mirrors [PublicClient.Resources].
	Resources []string

	// GrantTypes overrides the default
	// {"authorization_code", "refresh_token"}. Empty applies the
	// default; non-empty replaces it entirely.
	GrantTypes []string

	// ResponseTypes overrides the default {"code"}. Empty applies
	// the default; non-empty replaces it entirely.
	ResponseTypes []string

	// PostLogoutRedirectURIs mirrors [PublicClient.PostLogoutRedirectURIs].
	PostLogoutRedirectURIs []string

	// BackchannelLogoutURI mirrors [PublicClient.BackchannelLogoutURI].
	BackchannelLogoutURI string

	// BackchannelLogoutSessionRequired mirrors
	// [PublicClient.BackchannelLogoutSessionRequired]. The provider
	// currently rejects true.
	BackchannelLogoutSessionRequired bool

	// ApplicationType mirrors [PublicClient.ApplicationType].
	ApplicationType string

	// SubjectType requests the OIDC subject_type for this client; see
	// [PublicClient.SubjectType].
	SubjectType string

	// TokenEndpointAuthSigningAlg is meaningful only for private_key_jwt
	// clients; ConfidentialClient records it so callers can share seed
	// construction code across confidential and private-key clients.
	TokenEndpointAuthSigningAlg string

	// DefaultMaxAge mirrors [PublicClient.DefaultMaxAge].
	//
	// Stable since v1.5.
	DefaultMaxAge *int64

	// RequireAuthTime mirrors [PublicClient.RequireAuthTime].
	//
	// Stable since v1.5.
	RequireAuthTime bool

	// DefaultACRValues mirrors [PublicClient.DefaultACRValues].
	//
	// Stable since v1.5.
	DefaultACRValues []string
}

// seed projects c onto a [store.Client] with the confidential-client
// invariants applied: Secret hashed through [HashClientSecret], the
// resolved [AuthMethod] written verbatim to
// [store.Client.TokenEndpointAuthMethod], and Source set to
// [store.ClientSourceStatic].
// secretHash resolves the stored encoding for the seed, from whichever
// of the two mutually exclusive fields the caller filled in.
//
// Supplying both is rejected rather than resolved by precedence: the
// two fields disagree about which secret authenticates the client, and
// silently honouring one would leave the operator holding a plaintext
// they believe works and a client that cannot authenticate with it.
func (c ConfidentialClient) secretHash(method AuthMethod) (string, error) {
	switch {
	case c.Secret != "" && c.SecretHash != "":
		return "", newConfigurationError("ConfidentialClient "+c.ID+": Secret and SecretHash are mutually exclusive", nil)
	case c.SecretHash != "":
		return c.SecretHash, nil
	case c.Secret == "":
		// Hashing "" would store a credential that authenticates an empty client_secret.
		if method == AuthClientSecretBasic || method == AuthClientSecretPost {
			return "", newConfigurationError("ConfidentialClient "+c.ID+": Secret or SecretHash is required", nil)
		}
		return "", nil
	}
	hash, err := HashClientSecret(c.Secret)
	if err != nil {
		return "", newConfigurationError("ConfidentialClient: hashing client secret failed", err)
	}
	return hash, nil
}

// previousSecretHash resolves the stored encoding of the previous secret.
// Both fields empty means no previous secret; otherwise exactly one must be
// set and the expiry is required.
func (c ConfidentialClient) previousSecretHash() (string, error) {
	if c.PreviousSecret == "" && c.PreviousSecretHash == "" {
		return "", nil
	}
	if c.PreviousSecret != "" && c.PreviousSecretHash != "" {
		return "", newConfigurationError("ConfidentialClient "+c.ID+": PreviousSecret and PreviousSecretHash are mutually exclusive", nil)
	}
	if c.PreviousSecretExpiresAt.IsZero() {
		return "", newConfigurationError("ConfidentialClient "+c.ID+": PreviousSecretExpiresAt is required with a previous secret", nil)
	}
	if c.PreviousSecretHash != "" {
		return c.PreviousSecretHash, nil
	}
	hash, err := HashClientSecret(c.PreviousSecret)
	if err != nil {
		return "", newConfigurationError("ConfidentialClient: hashing previous client secret failed", err)
	}
	return hash, nil
}

// staticSeedSecrets carries the plaintexts a ConfidentialClient seed
// supplied, keyed by client_id, so reconciliation can reuse an existing
// salted hash that already verifies them. An empty field means the seed did
// not supply that plaintext.
type staticSeedSecrets struct {
	current  string
	previous string
}

// staticClientPreviousPlaintext is the previous-secret counterpart of
// staticClientPlaintext.
func staticClientPreviousPlaintext(seed ClientSeed) (string, bool) {
	switch value := seed.(type) {
	case ConfidentialClient:
		return value.PreviousSecret, value.PreviousSecret != ""
	case *ConfidentialClient:
		return value.PreviousSecret, value.PreviousSecret != ""
	default:
		return "", false
	}
}

func (c ConfidentialClient) seed() (store.Client, error) {
	if err := checkDefaultMaxAge("ConfidentialClient", c.ID, c.DefaultMaxAge); err != nil {
		return store.Client{}, err
	}
	method := c.AuthMethod
	if method == "" {
		method = AuthClientSecretBasic
	}
	hash, err := c.secretHash(method)
	if err != nil {
		return store.Client{}, err
	}
	previousHash, err := c.previousSecretHash()
	if err != nil {
		return store.Client{}, err
	}
	var previousExpiry time.Time
	if previousHash != "" {
		previousExpiry = c.PreviousSecretExpiresAt
	}
	grants, responses := seedGrantAndResponseTypes(c.GrantTypes, c.ResponseTypes)
	return store.Client{
		ID:                               c.ID,
		RedirectURIs:                     slices.Clone(c.RedirectURIs),
		Scopes:                           slices.Clone(c.Scopes),
		Resources:                        slices.Clone(c.Resources),
		GrantTypes:                       grants,
		ResponseTypes:                    responses,
		TokenEndpointAuthMethod:          method.String(),
		TokenEndpointAuthSigningAlg:      c.TokenEndpointAuthSigningAlg,
		SecretHash:                       hash,
		PreviousSecretHash:               previousHash,
		PreviousSecretExpiresAt:          previousExpiry,
		Source:                           store.ClientSourceStatic,
		PostLogoutRedirectURIs:           slices.Clone(c.PostLogoutRedirectURIs),
		BackchannelLogoutURI:             c.BackchannelLogoutURI,
		BackchannelLogoutSessionRequired: c.BackchannelLogoutSessionRequired,
		ApplicationType:                  c.ApplicationType,
		SubjectType:                      c.SubjectType,
		DefaultMaxAge:                    clone.Int64Ptr(c.DefaultMaxAge),
		RequireAuthTime:                  c.RequireAuthTime,
		DefaultACRValues:                 slices.Clone(c.DefaultACRValues),
	}, nil
}

// PrivateKeyJWTClient is the typed builder for a client that
// authenticates with a JWT assertion signed by its own private key
// (OIDC Core 1.0 §9 / RFC 7523). The OP never sees the private half;
// JWKS holds the public-half JSON Web Key Set the OP uses to verify
// assertions. [LoadPublicJWKS] accepts RSA, EC, and OKP keys, rebuilds
// each from a public-member allowlist, and returns the bytes ready to
// embed here. Symmetric and unsupported key types are rejected.
//
//	pub, err := op.LoadPublicJWKS("conformance/keys/fapi-client.jwks.json")
//	if err != nil { ... }
//	op.WithStaticClients(
//	    op.PrivateKeyJWTClient{
//	        ID:           "demo-fapi",
//	        JWKS:         pub,
//	        RedirectURIs: []string{"https://app.example.com/callback"},
//	        Scopes:       []string{"openid"},
//	    },
//	)
type PrivateKeyJWTClient struct {
	// ID is the OAuth client_id. MUST be unique within the OP.
	ID string

	// JWKS is the public-half JSON Web Key Set the OP uses to
	// verify private_key_jwt assertions. The bytes are stored
	// verbatim on [store.Client.JWKs]; pass the output of
	// [LoadPublicJWKS] (or an equivalent key-type-specific public
	// member normalizer) so private material never reaches the OP.
	JWKS []byte

	// RedirectURIs lists the exact-match redirect_uri values the
	// client may present at /authorize.
	RedirectURIs []string

	// Scopes lists the scopes the client is registered to request.
	Scopes []string

	// Resources mirrors [PublicClient.Resources].
	Resources []string

	// GrantTypes overrides the default
	// {"authorization_code", "refresh_token"}. Empty applies the
	// default; non-empty replaces it entirely.
	GrantTypes []string

	// ResponseTypes overrides the default {"code"}. Empty applies
	// the default; non-empty replaces it entirely.
	ResponseTypes []string

	// PostLogoutRedirectURIs mirrors [PublicClient.PostLogoutRedirectURIs].
	PostLogoutRedirectURIs []string

	// BackchannelLogoutURI mirrors [PublicClient.BackchannelLogoutURI].
	BackchannelLogoutURI string

	// BackchannelLogoutSessionRequired mirrors
	// [PublicClient.BackchannelLogoutSessionRequired]. The provider
	// currently rejects true.
	BackchannelLogoutSessionRequired bool

	// ApplicationType mirrors [PublicClient.ApplicationType].
	ApplicationType string

	// SubjectType requests the OIDC subject_type for this client; see
	// [PublicClient.SubjectType].
	SubjectType string

	// TokenEndpointAuthSigningAlg restricts client_assertion signatures
	// for this private_key_jwt client. Empty leaves the OP allow-list.
	TokenEndpointAuthSigningAlg string

	// DefaultMaxAge mirrors [PublicClient.DefaultMaxAge].
	//
	// Stable since v1.5.
	DefaultMaxAge *int64

	// RequireAuthTime mirrors [PublicClient.RequireAuthTime].
	//
	// Stable since v1.5.
	RequireAuthTime bool

	// DefaultACRValues mirrors [PublicClient.DefaultACRValues].
	//
	// Stable since v1.5.
	DefaultACRValues []string
}

// seed projects c onto a [store.Client] with the private_key_jwt
// invariants applied: TokenEndpointAuthMethod set to
// AuthPrivateKeyJWT, JWKS bytes embedded inline, and Source
// ClientSourceStatic.
func (c PrivateKeyJWTClient) seed() (store.Client, error) {
	if err := checkDefaultMaxAge("PrivateKeyJWTClient", c.ID, c.DefaultMaxAge); err != nil {
		return store.Client{}, err
	}
	grants, responses := seedGrantAndResponseTypes(c.GrantTypes, c.ResponseTypes)
	return store.Client{
		ID:                               c.ID,
		RedirectURIs:                     slices.Clone(c.RedirectURIs),
		Scopes:                           slices.Clone(c.Scopes),
		Resources:                        slices.Clone(c.Resources),
		GrantTypes:                       grants,
		ResponseTypes:                    responses,
		TokenEndpointAuthMethod:          AuthPrivateKeyJWT.String(),
		TokenEndpointAuthSigningAlg:      c.TokenEndpointAuthSigningAlg,
		JWKs:                             slices.Clone(c.JWKS),
		Source:                           store.ClientSourceStatic,
		PostLogoutRedirectURIs:           slices.Clone(c.PostLogoutRedirectURIs),
		BackchannelLogoutURI:             c.BackchannelLogoutURI,
		BackchannelLogoutSessionRequired: c.BackchannelLogoutSessionRequired,
		ApplicationType:                  c.ApplicationType,
		SubjectType:                      c.SubjectType,
		DefaultMaxAge:                    clone.Int64Ptr(c.DefaultMaxAge),
		RequireAuthTime:                  c.RequireAuthTime,
		DefaultACRValues:                 slices.Clone(c.DefaultACRValues),
	}, nil
}
