package op_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/grant"
)

const testAssertionIssuer = "https://partner-idp.example.com"

// testAssertionJWKS is a one-key JWK Set (RFC 7517 appendix A.1 P-256 key).
const testAssertionJWKS = `{"keys":[{"kty":"EC","crv":"P-256","kid":"k1","use":"sig",` +
	`"x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"}]}`

// validJWTBearerGrant returns a trust declaration every rung of
// validateJWTBearerGrant accepts; the rejection cases each break one field.
func validJWTBearerGrant() op.JWTBearerGrant {
	return op.JWTBearerGrant{
		Issuers: []op.AssertionIssuer{{
			Issuer:         testAssertionIssuer,
			JWKS:           []byte(testAssertionJWKS),
			AllowedClients: []string{"client-a"},
		}},
		ResolveSubject: func(context.Context, op.AssertionSubject) (string, error) {
			return "user-1", nil
		},
	}
}

func TestWithJWTBearerGrant_AcceptsValidConfig(t *testing.T) {
	t.Parallel()

	for _, profile := range []op.AssertionProfile{op.AssertionProfileJWT, op.AssertionProfileIDJAG} {
		g := validJWTBearerGrant()
		g.Issuers[0].Profile = profile
		if _, err := op.New(append(validBaseOpts(t), op.WithJWTBearerGrant(g))...); err != nil {
			t.Errorf("profile %d: op.New: %v", profile, err)
		}
	}

	g := validJWTBearerGrant()
	g.Issuers[0].JWKS = nil
	g.Issuers[0].JWKSURI = testAssertionIssuer + "/jwks.json"
	if _, err := op.New(append(validBaseOpts(t), op.WithJWTBearerGrant(g))...); err != nil {
		t.Errorf("JWKSURI issuer: op.New: %v", err)
	}
}

// TestWithJWTBearerGrant_RejectsInvalidTrustDeclaration drives each
// construction-time rejection of the trust declaration through op.New.
func TestWithJWTBearerGrant_RejectsInvalidTrustDeclaration(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		mutate func(*op.JWTBearerGrant)
		want   string
	}{
		{"no_issuers", func(g *op.JWTBearerGrant) { g.Issuers = nil }, "at least one AssertionIssuer"},
		{"nil_resolve_subject", func(g *op.JWTBearerGrant) { g.ResolveSubject = nil }, "ResolveSubject"},
		{"jwks_and_jwks_uri", func(g *op.JWTBearerGrant) {
			g.Issuers[0].JWKSURI = testAssertionIssuer + "/jwks.json"
		}, "exactly one of JWKSURI and JWKS"},
		{"neither_jwks_nor_jwks_uri", func(g *op.JWTBearerGrant) {
			g.Issuers[0].JWKS = nil
		}, "exactly one of JWKSURI and JWKS"},
		{"empty_issuer", func(g *op.JWTBearerGrant) { g.Issuers[0].Issuer = "" }, "Issuer must not be empty"},
		{"duplicate_issuer", func(g *op.JWTBearerGrant) {
			g.Issuers = append(g.Issuers, g.Issuers[0])
		}, "duplicate Issuer"},
		{"op_issuer", func(g *op.JWTBearerGrant) { g.Issuers[0].Issuer = validIssuer }, "must not equal the OP issuer"},
		{"http_jwks_uri", func(g *op.JWTBearerGrant) {
			g.Issuers[0].JWKS = nil
			g.Issuers[0].JWKSURI = "http://partner-idp.example.com/jwks.json"
		}, "JWKSURI must be an absolute https URL"},
		{"relative_jwks_uri", func(g *op.JWTBearerGrant) {
			g.Issuers[0].JWKS = nil
			g.Issuers[0].JWKSURI = "/jwks.json"
		}, "JWKSURI must be an absolute https URL"},
		{"empty_allowed_clients", func(g *op.JWTBearerGrant) {
			g.Issuers[0].AllowedClients = nil
		}, "AllowedClients must name at least one client_id"},
		{"empty_allowed_client_id", func(g *op.JWTBearerGrant) {
			g.Issuers[0].AllowedClients = []string{"client-a", ""}
		}, "AllowedClients must not contain an empty client_id"},
		{"unparseable_jwks", func(g *op.JWTBearerGrant) { g.Issuers[0].JWKS = []byte("not json") }, "Issuers[0].JWKS must parse"},
		{"empty_jwks", func(g *op.JWTBearerGrant) { g.Issuers[0].JWKS = []byte(`{"keys":[]}`) }, "Issuers[0].JWKS must parse"},
		{"undefined_profile", func(g *op.JWTBearerGrant) {
			g.Issuers[0].Profile = op.AssertionProfile(99)
		}, "Profile is not a defined AssertionProfile"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			g := validJWTBearerGrant()
			tc.mutate(&g)
			_, err := op.New(append(validBaseOpts(t), op.WithJWTBearerGrant(g))...)
			if err == nil {
				t.Fatal("op.New accepted an invalid WithJWTBearerGrant declaration")
			}
			if !op.IsServerError(err) {
				t.Errorf("err = %v, want a server configuration error", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestWithJWTBearerGrant_RejectsMissingUserStore(t *testing.T) {
	t.Parallel()

	_, err := op.New(
		op.WithIssuer(validIssuer),
		op.WithStore(stubStore{}),
		op.WithKeyset(validKeyset(t)),
		op.WithCookieKeys(newRandomCookieKey(t)),
		fixtureAuthenticator(),
		op.WithJWTBearerGrant(validJWTBearerGrant()),
	)
	if err == nil {
		t.Fatal("op.New accepted WithJWTBearerGrant without a UserStore")
	}
	if !strings.Contains(err.Error(), "WithJWTBearerGrant requires a UserStore") {
		t.Errorf("err = %v, want the jwt-bearer UserStore requirement", err)
	}
}

// TestWithJWTBearerGrant_RejectsGrantListedWithoutOption pins the
// WithGrants entry point: naming grant.JWTBearer there leaves the grant
// with no issuers to verify against, so op.New refuses it.
func TestWithJWTBearerGrant_RejectsGrantListedWithoutOption(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithGrants(grant.AuthorizationCode, grant.RefreshToken, grant.JWTBearer),
	)...)
	if err == nil {
		t.Fatal("op.New accepted grant.JWTBearer without WithJWTBearerGrant")
	}
	if !strings.Contains(err.Error(), "WithJWTBearerGrant") {
		t.Errorf("err = %v, want it to name WithJWTBearerGrant", err)
	}
}

func TestWithJWTBearerGrant_AcceptsGrantListedAlongsideOption(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithGrants(grant.AuthorizationCode, grant.RefreshToken, grant.JWTBearer),
		op.WithJWTBearerGrant(validJWTBearerGrant()),
	)...)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
}

func TestWithJWTBearerGrant_RejectsRepeat(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithJWTBearerGrant(validJWTBearerGrant()),
		op.WithJWTBearerGrant(validJWTBearerGrant()),
	)...)
	if err == nil {
		t.Fatal("op.New accepted WithJWTBearerGrant twice")
	}
}

// TestWithJWTBearerGrant_RejectsCustomGrantNamingTheWire pins that the
// jwt-bearer URN is reserved unconditionally: a custom handler under that
// name fails op.New whether it is registered before or after the
// built-in grant's option, and without that option at all.
func TestWithJWTBearerGrant_RejectsCustomGrantNamingTheWire(t *testing.T) {
	t.Parallel()

	custom := op.WithCustomGrant(fakeCustomGrant{name: grant.JWTBearer.String()})
	bearer := op.WithJWTBearerGrant(validJWTBearerGrant())
	for _, tc := range []struct {
		name string
		opts []op.Option
	}{
		{"custom_first", []op.Option{custom, bearer}},
		{"bearer_first", []op.Option{bearer, custom}},
		{"custom_alone", []op.Option{custom}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := op.New(append(validBaseOpts(t), tc.opts...)...)
			if !errors.Is(err, op.ErrCustomGrantBuiltinCollision) {
				t.Fatalf("op.New err = %v, want %v", err, op.ErrCustomGrantBuiltinCollision)
			}
		})
	}
}

// stubIDJAGPolicy satisfies [op.IDJAGIssuancePolicy] for the
// registration-only tests; no request reaches Allow.
type stubIDJAGPolicy struct{}

func (stubIDJAGPolicy) Allow(context.Context, op.IDJAGRequest) (*op.IDJAGDecision, error) {
	return nil, op.ErrIDJAGDenied
}

func TestWithIDJAGIssuance_AcceptsPolicy(t *testing.T) {
	t.Parallel()

	if _, err := op.New(append(validBaseOpts(t), op.WithIDJAGIssuance(stubIDJAGPolicy{}))...); err != nil {
		t.Fatalf("op.New: %v", err)
	}
}

func TestWithIDJAGIssuance_RejectsNilPolicy(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t), op.WithIDJAGIssuance(nil))...)
	if err == nil {
		t.Fatal("op.New accepted a nil IDJAGIssuancePolicy")
	}
	if !op.IsServerError(err) || !strings.Contains(err.Error(), "IDJAGIssuancePolicy") {
		t.Errorf("err = %v, want a configuration error naming IDJAGIssuancePolicy", err)
	}
}

func TestWithIDJAGIssuance_RejectsRepeat(t *testing.T) {
	t.Parallel()

	_, err := op.New(append(validBaseOpts(t),
		op.WithIDJAGIssuance(stubIDJAGPolicy{}),
		op.WithIDJAGIssuance(stubIDJAGPolicy{}),
	)...)
	if err == nil {
		t.Fatal("op.New accepted WithIDJAGIssuance twice")
	}
}

func TestWithIDJAGIssuance_SentinelsAreDistinct(t *testing.T) {
	t.Parallel()

	if errors.Is(op.ErrIDJAGDenied, op.ErrIDJAGUnknownAudience) {
		t.Error("ErrIDJAGDenied and ErrIDJAGUnknownAudience must map to different wire codes")
	}
}
