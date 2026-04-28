package op_test

import (
	"testing"

	"github.com/libraz/go-oidc-provider/op"
)

// TestClientSeed_PublicSurface pins the public-API shape of the
// three typed builders — every field that embedders set is exported
// and the zero value is a valid (if unsuitable) starting point for
// op.WithStaticClients. Deeper invariants (seed() output, secret
// hashing, defensive copies) live in client_seed_internal_test.go
// because they exercise the unexported seed() method.
func TestClientSeed_PublicSurface(t *testing.T) {
	t.Parallel()

	pub := op.PublicClient{
		ID:            "demo-spa",
		RedirectURIs:  []string{"https://app.example.com/cb"},
		Scopes:        []string{"openid"},
		GrantTypes:    []string{"authorization_code"},
		ResponseTypes: []string{"code"},
	}
	if pub.ID == "" {
		t.Fatal("PublicClient.ID is not assignable")
	}

	conf := op.ConfidentialClient{
		ID:           "demo-confidential",
		Secret:       "demo-secret",
		AuthMethod:   op.AuthClientSecretBasic,
		RedirectURIs: []string{"https://app.example.com/cb"},
		Scopes:       []string{"openid"},
	}
	if conf.AuthMethod != op.AuthClientSecretBasic {
		t.Fatal("ConfidentialClient.AuthMethod is not assignable")
	}

	pkj := op.PrivateKeyJWTClient{
		ID:           "demo-fapi",
		JWKS:         []byte(`{"keys":[]}`),
		RedirectURIs: []string{"https://app.example.com/cb"},
		Scopes:       []string{"openid"},
	}
	if len(pkj.JWKS) == 0 {
		t.Fatal("PrivateKeyJWTClient.JWKS is not assignable")
	}
}
