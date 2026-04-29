package op

import (
	"slices"

	"github.com/libraz/go-oidc-provider/op/store"
)

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
	return []string{"authorization_code", "refresh_token"}
}

// defaultResponseTypes() returns the wire-form response_types every
// typed builder defaults to when [PublicClient.ResponseTypes] et al.
// are left empty. v1.0 ships with "code" only; the helper returns a
// fresh slice so callers may freely mutate it.
func defaultResponseTypes() []string {
	return []string{"code"}
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
	// Logout Token (OIDC Back-Channel Logout 1.0 §2.4). Setting true
	// without [BackchannelLogoutURI] is a no-op; setting it is
	// recommended for clients that key downstream sessions on sid.
	BackchannelLogoutSessionRequired bool

	// ApplicationType mirrors OIDC Dynamic Client Registration 1.0's
	// "application_type" metadata. Typical values are "native" and
	// "web". The library does not enforce a specific value but
	// surfaces it through discovery / introspection so embedders can
	// drive their own routing on it.
	ApplicationType string

	// SubjectType requests a particular OIDC subject_type ("public"
	// or "pairwise"). v1.0 ships with "public" only — supplying any
	// other value is recorded but currently has no runtime effect; a
	// future pairwise rollout will honour it.
	SubjectType string
}

// seed projects c onto a [store.Client] with the public-client
// invariants (PublicClient: true, auth method "none", Source
// ClientSourceStatic) applied. The returned record is owned by the
// caller; subsequent mutation does not affect c.
func (c PublicClient) seed() (store.Client, error) {
	grants := c.GrantTypes
	if len(grants) == 0 {
		grants = defaultGrantTypes()
	} else {
		grants = slices.Clone(grants)
	}
	responses := c.ResponseTypes
	if len(responses) == 0 {
		responses = defaultResponseTypes()
	} else {
		responses = slices.Clone(responses)
	}
	return store.Client{
		ID:                               c.ID,
		RedirectURIs:                     slices.Clone(c.RedirectURIs),
		Scopes:                           slices.Clone(c.Scopes),
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
	Secret string

	// AuthMethod selects the token-endpoint authentication method.
	// Empty defaults to [AuthClientSecretBasic].
	AuthMethod AuthMethod

	// RedirectURIs lists the exact-match redirect_uri values the
	// client may present at /authorize.
	RedirectURIs []string

	// Scopes lists the scopes the client is registered to request.
	Scopes []string

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
	// [PublicClient.BackchannelLogoutSessionRequired].
	BackchannelLogoutSessionRequired bool

	// ApplicationType mirrors [PublicClient.ApplicationType].
	ApplicationType string

	// SubjectType mirrors [PublicClient.SubjectType].
	SubjectType string
}

// seed projects c onto a [store.Client] with the confidential-client
// invariants applied: Secret hashed through [HashClientSecret], the
// resolved [AuthMethod] written verbatim to
// [store.Client.TokenEndpointAuthMethod], and Source set to
// [store.ClientSourceStatic].
func (c ConfidentialClient) seed() (store.Client, error) {
	method := c.AuthMethod
	if method == "" {
		method = AuthClientSecretBasic
	}
	hash, err := HashClientSecret(c.Secret)
	if err != nil {
		return store.Client{}, &Error{
			Code:        codeConfiguration,
			Description: "ConfidentialClient: hashing client secret failed",
			Cause:       err,
		}
	}
	grants := c.GrantTypes
	if len(grants) == 0 {
		grants = defaultGrantTypes()
	} else {
		grants = slices.Clone(grants)
	}
	responses := c.ResponseTypes
	if len(responses) == 0 {
		responses = defaultResponseTypes()
	} else {
		responses = slices.Clone(responses)
	}
	return store.Client{
		ID:                               c.ID,
		RedirectURIs:                     slices.Clone(c.RedirectURIs),
		Scopes:                           slices.Clone(c.Scopes),
		GrantTypes:                       grants,
		ResponseTypes:                    responses,
		TokenEndpointAuthMethod:          method.String(),
		SecretHash:                       hash,
		Source:                           store.ClientSourceStatic,
		PostLogoutRedirectURIs:           slices.Clone(c.PostLogoutRedirectURIs),
		BackchannelLogoutURI:             c.BackchannelLogoutURI,
		BackchannelLogoutSessionRequired: c.BackchannelLogoutSessionRequired,
		ApplicationType:                  c.ApplicationType,
		SubjectType:                      c.SubjectType,
	}, nil
}

// PrivateKeyJWTClient is the typed builder for a client that
// authenticates with a JWT assertion signed by its own private key
// (OIDC Core 1.0 §9 / RFC 7523). The OP never sees the private half;
// JWKS holds the public-half JSON Web Key Set the OP uses to verify
// assertions. [LoadPublicJWKS] strips the "d" parameter from a
// JWKS file on disk and returns the bytes ready to embed here.
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
	// [LoadPublicJWKS] (or any equivalent that strips "d") so
	// private material never reaches the OP.
	JWKS []byte

	// RedirectURIs lists the exact-match redirect_uri values the
	// client may present at /authorize.
	RedirectURIs []string

	// Scopes lists the scopes the client is registered to request.
	Scopes []string

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
	// [PublicClient.BackchannelLogoutSessionRequired].
	BackchannelLogoutSessionRequired bool

	// ApplicationType mirrors [PublicClient.ApplicationType].
	ApplicationType string

	// SubjectType mirrors [PublicClient.SubjectType].
	SubjectType string
}

// seed projects c onto a [store.Client] with the private_key_jwt
// invariants applied: TokenEndpointAuthMethod set to
// AuthPrivateKeyJWT, JWKS bytes embedded inline, and Source
// ClientSourceStatic.
func (c PrivateKeyJWTClient) seed() (store.Client, error) {
	grants := c.GrantTypes
	if len(grants) == 0 {
		grants = defaultGrantTypes()
	} else {
		grants = slices.Clone(grants)
	}
	responses := c.ResponseTypes
	if len(responses) == 0 {
		responses = defaultResponseTypes()
	} else {
		responses = slices.Clone(responses)
	}
	return store.Client{
		ID:                               c.ID,
		RedirectURIs:                     slices.Clone(c.RedirectURIs),
		Scopes:                           slices.Clone(c.Scopes),
		GrantTypes:                       grants,
		ResponseTypes:                    responses,
		TokenEndpointAuthMethod:          AuthPrivateKeyJWT.String(),
		JWKs:                             slices.Clone(c.JWKS),
		Source:                           store.ClientSourceStatic,
		PostLogoutRedirectURIs:           slices.Clone(c.PostLogoutRedirectURIs),
		BackchannelLogoutURI:             c.BackchannelLogoutURI,
		BackchannelLogoutSessionRequired: c.BackchannelLogoutSessionRequired,
		ApplicationType:                  c.ApplicationType,
		SubjectType:                      c.SubjectType,
	}, nil
}
