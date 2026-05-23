package tokenendpoint

import (
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
)

func TestRefreshDPoPJKT_BindsPublicClientEvenWhenAuthMethodUnset(t *testing.T) {
	t.Parallel()

	client := &store.Client{ID: "public-dcr", PublicClient: true}

	if got := refreshDPoPJKT(client, "jkt-1"); got != "jkt-1" {
		t.Fatalf("refreshDPoPJKT=%q want jkt-1", got)
	}
}
