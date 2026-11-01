package endpointsupport_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/internal/revocation"
	"github.com/libraz/go-oidc-provider/op/store"
)

func TestNewAccessTokenVerifierCopiesFields(t *testing.T) {
	for _, strategy := range []store.AccessTokenRevocationStrategy{
		store.RevocationStrategyGrantTombstone,
		store.RevocationStrategyJTIRegistry,
	} {
		v := endpointsupport.NewAccessTokenVerifier(nil, "https://op.example.com", nil, 7*time.Second, strategy)
		if v.Issuer != "https://op.example.com" || v.Leeway != 7*time.Second {
			t.Fatalf("issuer/leeway not propagated: %+v", v)
		}
		if v.Clock != nil {
			t.Fatalf("nil clock must stay nil, got %v", v.Clock)
		}
		if v.RequireJTI != revocation.RequireJTIFor(strategy) {
			t.Fatalf("RequireJTI = %v for strategy %v", v.RequireJTI, strategy)
		}
	}
}

func TestOrderTokenBranches(t *testing.T) {
	cases := []struct {
		name                  string
		refreshHinted, jwtish bool
		want                  []string
	}{
		{"opaque only when not JWS-shaped", false, false, []string{"opaque"}},
		{"refresh hint ignores JWT when not JWS-shaped", true, false, []string{"opaque"}},
		{"JWT first by default", false, true, []string{"jwt", "opaque"}},
		{"refresh hint puts opaque first", true, true, []string{"opaque", "jwt"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := endpointsupport.OrderTokenBranches(tc.refreshHinted, tc.jwtish, "jwt", "opaque")
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}
