package registrationendpoint_test

import (
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
)

// TestManage_Update_KeepsOperatorConfiguration walks the path an
// operator actually takes: a client self-registers, the operator then
// configures it further through the store (a resource-indicator allow-list
// survives because it is not registration metadata, while the JWT
// introspection switch is wire-expressed), and the client later updates its
// own display name. The update preserves only operator-only configuration
// and clears omitted registration metadata per RFC 7592 §2.2.
func TestManage_Update_KeepsOperatorConfiguration(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	f := newFixture(t, op.RegistrationOption{})
	created := f.register(t, nil)

	configured, err := f.prov.Store.GetClient(ctx, created.clientID)
	if err != nil {
		t.Fatalf("GetClient(%q): %v", created.clientID, err)
	}
	configured.Resources = []string{"https://api.test.invalid"}
	configured.IntrospectionSignedResponseAlg = "ES256"
	if err := f.prov.Store.UpdateClient(ctx, configured); err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}

	resp := f.manage(t, http.MethodPut, created.registrationClientURI, created.registrationAccessToken,
		map[string]any{
			"redirect_uris": []string{"https://rp.test.invalid/callback"},
			"client_name":   "renamed by the client",
		})
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d want 200 body=%s", resp.StatusCode, raw)
	}

	stored, err := f.prov.Store.GetClient(ctx, created.clientID)
	if err != nil {
		t.Fatalf("GetClient(%q) after update: %v", created.clientID, err)
	}
	if len(stored.Resources) != 1 || stored.Resources[0] != "https://api.test.invalid" {
		t.Errorf("Resources=%v after update, want the operator-configured allow-list; the update "+
			"rebuilt the record from the submitted metadata instead of editing it", stored.Resources)
	}
	if stored.IntrospectionSignedResponseAlg != "" {
		t.Errorf("IntrospectionSignedResponseAlg=%q after omitted PUT, want empty",
			stored.IntrospectionSignedResponseAlg)
	}
	// The submitted members are still applied, so the preservation above
	// is not simply an update that did nothing.
	if stored.ClientName != "renamed by the client" {
		t.Errorf("ClientName=%q, want the submitted value", stored.ClientName)
	}
}
