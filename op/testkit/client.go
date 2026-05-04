package testkit

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
)

// ClientFixture is the testkit-side description of a client to register.
// It carries only the fields tests typically vary; everything else is
// derived to a sensible default by [RegisterClient].
//
// Zero values pick the testkit's defaults:
//
//   - ID:                       "client-test"
//   - RedirectURIs:              ["https://rp.testkit.invalid/callback"]
//   - GrantTypes:                ["authorization_code", "refresh_token"]
//   - ResponseTypes:             ["code"]
//   - Scopes:                    ["openid", "profile", "email"]
//   - TokenEndpointAuthMethod:   "client_secret_basic" (or "none" if PublicClient)
//   - PublicClient:              false
//   - JWKs:                      nil (set when registering a private_key_jwt client)
type ClientFixture struct {
	ID                      string
	RedirectURIs            []string
	PostLogoutRedirectURIs  []string
	GrantTypes              []string
	ResponseTypes           []string
	Scopes                  []string
	Resources               []string
	TokenEndpointAuthMethod string
	SecretHash              string
	PublicClient            bool

	// SectorIdentifierURI is the optional pairwise sector identifier
	// per OIDC Core 1.0 §8.1. The value is forwarded verbatim to
	// [store.Client.SectorIdentifierURI]; tests that exercise the
	// pairwise issuance path supply it so the OP's SubjectGenerator
	// derives the sector host from this field rather than from the
	// (single-host) redirect URIs.
	SectorIdentifierURI string

	// SubjectType is the OIDC Core 1.0 §8 subject_type the client
	// requests at registration ("public" or "pairwise"). The empty
	// string is normalised to "public" by the OP's issuance projector,
	// so tests that want pairwise issuance against an OP enrolled with
	// [op.WithPairwiseSubject] MUST set the field to "pairwise"
	// explicitly — the global pairwise option no longer forces every
	// client onto the pairwise path.
	SubjectType string

	// JWKs is the raw JWK Set the client publishes for private_key_jwt /
	// request-object verification. The testkit stores the bytes verbatim
	// onto [store.Client.JWKs]; consumers parse them lazily. Leave nil
	// for clients that authenticate via shared secret.
	JWKs json.RawMessage

	// IDTokenEncryptedResponseAlg is the JWE `alg` the client requests
	// for issued ID tokens (OIDC Core 1.0 §10.2). Empty selects the
	// plain signed-JWT id_token path.
	IDTokenEncryptedResponseAlg string

	// IDTokenEncryptedResponseEnc is the JWE `enc` paired with
	// [IDTokenEncryptedResponseAlg].
	IDTokenEncryptedResponseEnc string

	// UserInfoEncryptedResponseAlg is the JWE `alg` the client
	// requests for /userinfo responses when negotiating the
	// application/jwt media type (OIDC Core 1.0 §5.3.4).
	UserInfoEncryptedResponseAlg string

	// UserInfoEncryptedResponseEnc is the JWE `enc` paired with
	// [UserInfoEncryptedResponseAlg].
	UserInfoEncryptedResponseEnc string

	// AuthorizationEncryptedResponseAlg is the JWE `alg` the client
	// requests for JARM authorization responses (FAPI 2.0 Message
	// Signing §5.5).
	AuthorizationEncryptedResponseAlg string

	// AuthorizationEncryptedResponseEnc is the JWE `enc` paired with
	// [AuthorizationEncryptedResponseAlg].
	AuthorizationEncryptedResponseEnc string

	// IntrospectionEncryptedResponseAlg is the JWE `alg` the client
	// requests for JWT introspection responses (RFC 9701 §5).
	IntrospectionEncryptedResponseAlg string

	// IntrospectionEncryptedResponseEnc is the JWE `enc` paired with
	// [IntrospectionEncryptedResponseAlg].
	IntrospectionEncryptedResponseEnc string
}

// RegisterClient seeds the testkit's [inmem.Store] with a client built from
// fix and returns the resulting [*store.Client]. It fails the test fast
// when the underlying store rejects the entry (typically because the
// caller registered a duplicate ID).
func (p *Provider) RegisterClient(tb testing.TB, fix ClientFixture) *store.Client {
	tb.Helper()
	c := buildClient(fix)
	if err := p.Store.RegisterClient(context.Background(), c); err != nil {
		tb.Fatalf("testkit: RegisterClient(%q): %v", c.ID, err)
	}
	return cloneClient(c)
}

// buildClient applies the testkit defaults to a ClientFixture and returns a
// [*store.Client] ready to be registered. It is package-private so tests
// against the helper can poke at the defaults.
func buildClient(fix ClientFixture) *store.Client {
	out := &store.Client{
		ID:                      coalesce(fix.ID, "client-test"),
		ClientIDIssuedAt:        0,
		RedirectURIs:            slices.Clone(fix.RedirectURIs),
		PostLogoutRedirectURIs:  slices.Clone(fix.PostLogoutRedirectURIs),
		GrantTypes:              slices.Clone(fix.GrantTypes),
		ResponseTypes:           slices.Clone(fix.ResponseTypes),
		Scopes:                  slices.Clone(fix.Scopes),
		Resources:               slices.Clone(fix.Resources),
		TokenEndpointAuthMethod: fix.TokenEndpointAuthMethod,
		SecretHash:              fix.SecretHash,
		PublicClient:            fix.PublicClient,
		SectorIdentifierURI:     fix.SectorIdentifierURI,
		SubjectType:             fix.SubjectType,
		JWKs:                    append(json.RawMessage(nil), fix.JWKs...),

		IDTokenEncryptedResponseAlg:       fix.IDTokenEncryptedResponseAlg,
		IDTokenEncryptedResponseEnc:       fix.IDTokenEncryptedResponseEnc,
		UserInfoEncryptedResponseAlg:      fix.UserInfoEncryptedResponseAlg,
		UserInfoEncryptedResponseEnc:      fix.UserInfoEncryptedResponseEnc,
		AuthorizationEncryptedResponseAlg: fix.AuthorizationEncryptedResponseAlg,
		AuthorizationEncryptedResponseEnc: fix.AuthorizationEncryptedResponseEnc,
		IntrospectionEncryptedResponseAlg: fix.IntrospectionEncryptedResponseAlg,
		IntrospectionEncryptedResponseEnc: fix.IntrospectionEncryptedResponseEnc,
	}
	if len(out.RedirectURIs) == 0 {
		out.RedirectURIs = []string{"https://rp.testkit.invalid/callback"}
	}
	if len(out.GrantTypes) == 0 {
		out.GrantTypes = []string{"authorization_code", "refresh_token"}
	}
	if len(out.ResponseTypes) == 0 {
		out.ResponseTypes = []string{"code"}
	}
	if len(out.Scopes) == 0 {
		out.Scopes = []string{"openid", "profile", "email"}
	}
	if out.TokenEndpointAuthMethod == "" {
		if out.PublicClient {
			out.TokenEndpointAuthMethod = "none"
		} else {
			out.TokenEndpointAuthMethod = "client_secret_basic"
		}
	}
	return out
}

// coalesce returns first when it is non-empty, otherwise fallback. It
// keeps the [buildClient] body free of repetitive ternary expressions.
func coalesce(first, fallback string) string {
	if first != "" {
		return first
	}
	return fallback
}

// cloneClient returns a deep copy of c so callers cannot mutate the
// pointer the in-memory store holds.
func cloneClient(c *store.Client) *store.Client {
	cp := *c
	cp.RedirectURIs = slices.Clone(c.RedirectURIs)
	cp.PostLogoutRedirectURIs = slices.Clone(c.PostLogoutRedirectURIs)
	cp.GrantTypes = slices.Clone(c.GrantTypes)
	cp.ResponseTypes = slices.Clone(c.ResponseTypes)
	cp.Scopes = slices.Clone(c.Scopes)
	cp.Resources = slices.Clone(c.Resources)
	if c.JWKs != nil {
		cp.JWKs = append(json.RawMessage(nil), c.JWKs...)
	}
	return &cp
}
