package clientauth_test

import (
	"testing"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/op/store"
)

func TestIsPublicClient(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		client *store.Client
		want   bool
	}{
		{"nil", nil, false},
		{"flagged public", &store.Client{PublicClient: true}, true},
		{"auth method none", &store.Client{TokenEndpointAuthMethod: "none"}, true},
		{"confidential", &store.Client{TokenEndpointAuthMethod: "client_secret_basic"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := clientauth.IsPublicClient(tc.client); got != tc.want {
				t.Fatalf("IsPublicClient = %v, want %v", got, tc.want)
			}
		})
	}
}
