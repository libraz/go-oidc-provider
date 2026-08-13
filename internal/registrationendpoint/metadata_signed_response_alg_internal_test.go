package registrationendpoint

import (
	"slices"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/discovery"
)

// TestSignedResponseAlgSurfacesAgreeWithDiscovery holds the accepted
// set and the advertised set against each other. An algorithm published
// in a *_signing_alg_values_supported array that registration refuses
// misleads an RP exactly as much as a registration the OP accepts and
// then ignores, so both directions are asserted from the discovery
// document the OP actually builds.
//
// The UserInfo row uses the surface for a client that registered
// response encryption. That is the client shape whose /userinfo
// responses are signed on every call; without registered encryption the
// signed shape is chosen per request by the Accept header and the member
// names no algorithm at all.
func TestSignedResponseAlgSurfacesAgreeWithDiscovery(t *testing.T) {
	t.Parallel()

	doc := discovery.Build(discovery.Input{
		Issuer: "https://op.test.invalid",
		Features: discovery.Features{
			AuthorizeEndpoint: true,
			JARM:              true,
			Introspect:        true,
		},
	})
	cases := []struct {
		member     string
		advertised []string
		surface    signedResponseAlgSurface
	}{
		{
			member:     "id_token_signing_alg_values_supported",
			advertised: doc.IDTokenSigningAlgValuesSupported,
			surface:    idTokenSignedResponseSurface(),
		},
		{
			member:     "userinfo_signing_alg_values_supported",
			advertised: doc.UserInfoSigningAlgValuesSupported,
			surface:    userInfoSignedResponseSurface(true),
		},
		{
			member:     "authorization_signing_alg_values_supported",
			advertised: doc.AuthorizationSigningAlgValuesSupported,
			surface:    authorizationSignedResponseSurface(),
		},
		{
			member:     "introspection_signing_alg_values_supported",
			advertised: doc.IntrospectionSigningAlgValuesSupported,
			surface:    introspectionSignedResponseSurface(),
		},
	}
	// Algorithms an RP library commonly offers. None of them may be
	// registrable on a surface that does not advertise it.
	unadvertised := []string{"RS256", "PS256", "ES384", "EdDSA", "HS256"}

	for _, tc := range cases {
		if len(tc.advertised) == 0 {
			t.Errorf("%s is empty; the surface accepts an algorithm no RP can discover", tc.member)
			continue
		}
		for _, alg := range tc.advertised {
			if err := validateSignedResponseAlg(tc.surface, alg); err != nil {
				t.Errorf("%s advertises %q but registration refuses it: %v", tc.member, alg, err)
			}
		}
		for _, alg := range unadvertised {
			if slices.Contains(tc.advertised, alg) {
				continue
			}
			if err := validateSignedResponseAlg(tc.surface, alg); err == nil {
				t.Errorf("%s does not advertise %q but registration accepts it", tc.member, alg)
			}
		}
	}
}
