package authorize_test

import (
	"errors"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authorize"
)

// TestValidate_OpenIDScopeIsClampedToClientRegistration requests
// "openid profile" from a client registered for "profile" only. The
// openid scope enjoys no exemption from the client-allowed clamp: the
// request is refused with ErrScopeNotPermitted whether or not the
// openid presence check is lifted, so ID-token issuance can never be
// decided on the raw requested scope.
//
// Tracks: GHSA-q686-2qmg-hqc7 (Authlib — the implicit grant decided ID token issuance on the raw requested scope instead of the client-allowed scope)
func TestValidate_OpenIDScopeIsClampedToClientRegistration(t *testing.T) {
	t.Parallel()

	policies := map[string]authorize.Policy{
		"openid_required": {PKCERequired: true},
		"openid_optional": {PKCERequired: true, OpenIDScopeOptional: true},
	}
	for name, policy := range policies {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			client := goodClient()
			client.Scopes = []string{"profile"}
			v := goodValues()
			v.Set("scope", "openid profile")
			req, err := authorize.ParseValues(v)
			if err != nil {
				t.Fatalf("ParseValues: %v", err)
			}
			if err := req.Validate(client, nil, policy); !errors.Is(err, authorize.ErrScopeNotPermitted) {
				t.Fatalf("Validate err=%v, want ErrScopeNotPermitted", err)
			}
		})
	}
}
