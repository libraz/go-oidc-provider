package testkit

import (
	"context"
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
type ClientFixture struct {
	ID                      string
	RedirectURIs            []string
	PostLogoutRedirectURIs  []string
	GrantTypes              []string
	ResponseTypes           []string
	Scopes                  []string
	TokenEndpointAuthMethod string
	SecretHash              string
	PublicClient            bool
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
		RedirectURIs:            slices.Clone(fix.RedirectURIs),
		PostLogoutRedirectURIs:  slices.Clone(fix.PostLogoutRedirectURIs),
		GrantTypes:              slices.Clone(fix.GrantTypes),
		ResponseTypes:           slices.Clone(fix.ResponseTypes),
		Scopes:                  slices.Clone(fix.Scopes),
		TokenEndpointAuthMethod: fix.TokenEndpointAuthMethod,
		SecretHash:              fix.SecretHash,
		PublicClient:            fix.PublicClient,
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
	return &cp
}
