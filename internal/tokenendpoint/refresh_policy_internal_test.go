package tokenendpoint

import (
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
)

// TestClientPermitsRefresh_PolicyMatrix pins the complete
// authorization-code refresh-token issuance policy. The global
// op.WithGrants gate is validated separately at Provider
// construction; this matrix covers the per-client and per-request
// predicate.
func TestClientPermitsRefresh_PolicyMatrix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                string
		grantTypes          []string
		scope               []string
		strictOfflineAccess bool
		want                bool
	}{
		{
			name:       "client grant missing",
			grantTypes: []string{"authorization_code"},
			scope:      []string{"openid", "offline_access"},
		},
		{
			name:       "openid missing in lax mode",
			grantTypes: []string{"refresh_token"},
			scope:      []string{"offline_access"},
		},
		{
			name:                "openid missing in strict mode",
			grantTypes:          []string{"refresh_token"},
			scope:               []string{"offline_access"},
			strictOfflineAccess: true,
		},
		{
			name:       "lax default without offline access",
			grantTypes: []string{"authorization_code", "refresh_token"},
			scope:      []string{"openid"},
			want:       true,
		},
		{
			name:       "lax default with offline access",
			grantTypes: []string{"authorization_code", "refresh_token"},
			scope:      []string{"openid", "offline_access"},
			want:       true,
		},
		{
			name:                "strict mode without offline access",
			grantTypes:          []string{"authorization_code", "refresh_token"},
			scope:               []string{"openid"},
			strictOfflineAccess: true,
		},
		{
			name:                "strict mode with offline access",
			grantTypes:          []string{"authorization_code", "refresh_token"},
			scope:               []string{"openid", "offline_access"},
			strictOfflineAccess: true,
			want:                true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client := &store.Client{GrantTypes: tt.grantTypes}
			if got := clientPermitsRefresh(client, tt.scope, tt.strictOfflineAccess); got != tt.want {
				t.Errorf(
					"clientPermitsRefresh(grants=%v, scope=%v, strict=%t)=%t want %t",
					tt.grantTypes,
					tt.scope,
					tt.strictOfflineAccess,
					got,
					tt.want,
				)
			}
		})
	}
}
