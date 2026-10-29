package tokenendpoint_test

import (
	"net/http"
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
)

// TestRefresh_ExchangeChainReturnsNoIDToken pins that refreshing a
// token-exchange chain (access-token extras carry act) returns no id_token,
// while a custom-grant chain without a delegation record still does.
func TestRefresh_ExchangeChainReturnsNoIDToken(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		extra     map[string]any
		wantToken bool
	}{
		"delegated exchange": {extra: map[string]any{"act": map[string]any{"sub": "actor"}}, wantToken: false},
		"plain custom grant": {extra: nil, wantToken: true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			client, secret := f.confidentialClientFixture(t)
			const tokenID = "rt-exchange-chain"
			f.seedRefreshToken(t, &store.RefreshToken{
				ID:               tokenID,
				ClientID:         client.ID,
				Subject:          "user-1",
				GrantID:          "grant-exchange-chain",
				Scope:            []string{"openid"},
				Origin:           store.RefreshOriginCustomGrant,
				SubjectPublic:    true,
				AccessTokenExtra: tc.extra,
			})
			resp := f.post(t, refreshForm(tokenID, ""), client.ID, secret)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status=%d want 200, body=%v", resp.StatusCode, decodeJSON(t, resp))
			}
			body := decodeJSON(t, resp)
			if got, _ := body["id_token"].(string); (got != "") != tc.wantToken {
				t.Fatalf("id_token present=%v, want %v", got != "", tc.wantToken)
			}
		})
	}
}
