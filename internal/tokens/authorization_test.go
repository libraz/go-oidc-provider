package tokens_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
)

func TestResolveAuthorization(t *testing.T) {
	t.Parallel()

	t1 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	t2 := t1.Add(time.Hour)
	d1 := map[string]any{"type": "payment", "amount": "1"}
	d2 := map[string]any{"type": "payment", "amount": "2"}
	d3 := map[string]any{"type": "payment", "amount": "3"}
	grantClaims := map[string]any{"request": map[string]any{"userinfo": map[string]any{"email": nil}}}
	ownClaims := map[string]any{"request": map[string]any{"userinfo": map[string]any{"phone_number": nil}}}
	grant := &store.Grant{
		ClientID: "rp", AuthTime: t2, ACR: "mfa", AMR: []string{"otp"},
		AuthorizationDetails: []map[string]any{d1, d3}, Claims: grantClaims,
	}
	own := tokens.Authorization{
		AuthTime: t1, ACR: "pwd", AMR: []string{"pwd"},
		AuthorizationDetails: []map[string]any{d1, d2}, Claims: ownClaims,
	}

	for _, tc := range []struct {
		name     string
		own      tokens.Authorization
		recorded bool
		grant    *store.Grant
		clientID string
		want     tokens.Authorization
	}{
		{
			name: "recorded keeps its own state and is narrowed, not widened, by the grant",
			own:  own, recorded: true, grant: grant, clientID: "rp",
			want: tokens.Authorization{
				AuthTime: t1, ACR: "pwd", AMR: []string{"pwd"},
				AuthorizationDetails: []map[string]any{d1}, Claims: ownClaims,
			},
		},
		{
			name: "recorded with nothing stays empty",
			own:  tokens.Authorization{}, recorded: true, grant: grant, clientID: "rp",
			want: tokens.Authorization{},
		},
		{
			name: "unrecorded takes what the grant holds",
			own:  tokens.Authorization{}, recorded: false, grant: grant, clientID: "rp",
			want: tokens.Authorization{
				AuthTime: t2, ACR: "mfa", AMR: []string{"otp"},
				AuthorizationDetails: []map[string]any{d1, d3}, Claims: grantClaims,
			},
		},
		{
			name: "another client's grant is never consulted",
			own:  tokens.Authorization{}, recorded: false, grant: grant, clientID: "other",
			want: tokens.Authorization{},
		},
	} {
		got := tokens.ResolveAuthorization(tc.own, tc.recorded, tc.grant, tc.clientID)
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s:\n got %+v\nwant %+v", tc.name, got, tc.want)
		}
	}
}
