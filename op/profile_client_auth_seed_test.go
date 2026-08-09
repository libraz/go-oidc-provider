package op_test

import (
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/profile"
)

// staticSeedForAuthMethod returns the [op.WithStaticClients] option that
// registers a client authenticating with method. Every value
// [profile.AllowedClientAuthMethods] returns must be reachable here:
// the profile list is documented as a usable seed source, so a method
// with no constructible seed means the profile advertises something the
// OP cannot serve.
func staticSeedForAuthMethod(tb testing.TB, method, id string) op.Option {
	tb.Helper()
	const redirect = "https://app.example.com/cb"
	switch op.AuthMethod(method) {
	case op.AuthPrivateKeyJWT:
		return op.WithStaticClients(op.PrivateKeyJWTClient{
			ID:           id,
			JWKS:         validStaticJWKS(tb),
			RedirectURIs: []string{redirect},
			Scopes:       []string{"openid"},
		})
	case op.AuthClientSecretBasic, op.AuthClientSecretPost:
		//nolint:gosec // G101: test-fixture client secret, never a real credential.
		return op.WithStaticClients(op.ConfidentialClient{
			ID:           id,
			Secret:       "seeded-client-secret",
			AuthMethod:   op.AuthMethod(method),
			RedirectURIs: []string{redirect},
			Scopes:       []string{"openid"},
		})
	case op.AuthNone:
		return op.WithStaticClients(op.PublicClient{
			ID:           id,
			RedirectURIs: []string{redirect},
			Scopes:       []string{"openid"},
		})
	default:
		tb.Fatalf("no client seed can express token_endpoint_auth_method %q, "+
			"yet a profile advertises it as allowed", method)
		return nil
	}
}

// TestAllowedClientAuthMethods_SeedsConstructThroughNew pins the
// contract that makes [profile.AllowedClientAuthMethods] usable: every
// method it names can seed a client that survives [op.New]. A profile
// that listed a method the OP refuses would leave an embedder unable to
// register any client at all by following the profile's own list — the
// list would say "use one of these" while construction rejected each in
// turn.
func TestAllowedClientAuthMethods_SeedsConstructThroughNew(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		p      profile.Profile
		wiring []op.Option
	}{
		{
			name: "FAPI2Baseline",
			p:    profile.FAPI2Baseline,
			wiring: []op.Option{
				op.WithProfile(profile.FAPI2Baseline),
				op.WithFeature(feature.DPoP),
			},
		},
		{
			name: "FAPI2MessageSigning",
			p:    profile.FAPI2MessageSigning,
			wiring: []op.Option{
				op.WithProfile(profile.FAPI2MessageSigning),
				op.WithFeature(feature.DPoP),
				op.WithDPoPNonceSource(stubDPoPNonceSource{}),
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			methods := profile.AllowedClientAuthMethods(tc.p)
			if len(methods) == 0 {
				t.Fatalf("%s constrains client authentication but names no method", tc.p)
			}
			for _, method := range methods {
				t.Run(method, func(t *testing.T) {
					t.Parallel()

					opts := append(validBaseOptsWithInmem(t), tc.wiring...)
					opts = append(opts, staticSeedForAuthMethod(t, method, "seed-"+method))
					if _, err := op.New(opts...); err != nil {
						t.Fatalf("op.New rejected a client seeded with %q, which %s advertises: %v",
							method, tc.p, err)
					}
				})
			}
		})
	}
}
