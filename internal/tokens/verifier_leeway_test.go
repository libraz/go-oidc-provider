package tokens_test

import (
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
)

func TestNewAccessTokenVerifier_LeewayDefault(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		leeway time.Duration
		want   time.Duration
	}{
		{"zero resolves to default", 0, tokens.DefaultLeeway},
		{"negative resolves to default", -time.Second, tokens.DefaultLeeway},
		{"explicit value kept", 5 * time.Second, 5 * time.Second},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v := endpointsupport.NewAccessTokenVerifier(nil, "iss", nil, tc.leeway, store.AccessTokenRevocationStrategy(0))
			if v.Leeway != tc.want {
				t.Fatalf("Leeway = %v, want %v", v.Leeway, tc.want)
			}
		})
	}
}
