package registrationendpoint_test

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
)

// TestManagePUT_PreviousSecret pins how an RFC 7592 update treats the
// previous-secret pair: it survives a confidential-to-confidential edit and
// is cleared whenever the current secret is removed or newly minted. A
// client_secret in the body is matched against the current hash only.
func TestManagePUT_PreviousSecret(t *testing.T) {
	t.Parallel()

	const (
		currentSecret  = "current-secret-value"
		previousSecret = "previous-secret-value"
		callback       = "https://rp.test.invalid/cb"
	)
	expiry := time.Date(2026, 4, 27, 12, 0, 0, 0, time.UTC)

	// seeded registers a client with the given auth method and writes the
	// previous pair (and, for a confidential client, the current hash)
	// straight into the store.
	seeded := func(t *testing.T, method string) (*dcrFixture, dcrCreated) {
		t.Helper()
		ctx := context.Background()
		f := newFixture(t, op.DynamicRegistration{})
		created := f.register(t, map[string]any{
			"redirect_uris":              []string{callback},
			"token_endpoint_auth_method": method,
		})
		stored, err := f.prov.Store.GetClient(ctx, created.clientID)
		if err != nil {
			t.Fatalf("GetClient: %v", err)
		}
		if method != "none" {
			if stored.SecretHash, err = op.HashClientSecret(currentSecret); err != nil {
				t.Fatalf("HashClientSecret: %v", err)
			}
		}
		if stored.PreviousSecretHash, err = op.HashClientSecret(previousSecret); err != nil {
			t.Fatalf("HashClientSecret: %v", err)
		}
		stored.PreviousSecretExpiresAt = expiry
		if err := f.prov.Store.UpdateClient(ctx, stored); err != nil {
			t.Fatalf("UpdateClient: %v", err)
		}
		return f, created
	}
	put := func(t *testing.T, f *dcrFixture, c dcrCreated, body map[string]any) *http.Response {
		t.Helper()
		return f.manage(t, http.MethodPut, c.registrationClientURI, c.registrationAccessToken, body)
	}

	t.Run("confidential to confidential keeps the pair", func(t *testing.T) {
		t.Parallel()
		f, created := seeded(t, "client_secret_basic")
		resp := put(t, f, created, map[string]any{
			"redirect_uris":              []string{callback},
			"token_endpoint_auth_method": "client_secret_basic",
			"client_name":                "renamed",
			"client_secret":              currentSecret,
		})
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			t.Fatalf("status=%d want 200 body=%s", resp.StatusCode, raw)
		}
		got, err := f.prov.Store.GetClient(context.Background(), created.clientID)
		if err != nil {
			t.Fatalf("GetClient: %v", err)
		}
		if !op.VerifyPassword([]byte(got.PreviousSecretHash), previousSecret) {
			t.Error("previous hash was not preserved")
		}
		if !got.PreviousSecretExpiresAt.Equal(expiry) {
			t.Errorf("PreviousSecretExpiresAt=%v want %v", got.PreviousSecretExpiresAt, expiry)
		}
		if got.ClientName != "renamed" {
			t.Errorf("ClientName=%q, update was not applied", got.ClientName)
		}
	})

	t.Run("confidential to public clears the pair", func(t *testing.T) {
		t.Parallel()
		f, created := seeded(t, "client_secret_basic")
		resp := put(t, f, created, map[string]any{
			"redirect_uris":              []string{callback},
			"token_endpoint_auth_method": "none",
		})
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			t.Fatalf("status=%d want 200 body=%s", resp.StatusCode, raw)
		}
		got, err := f.prov.Store.GetClient(context.Background(), created.clientID)
		if err != nil {
			t.Fatalf("GetClient: %v", err)
		}
		if got.SecretHash != "" || got.PreviousSecretHash != "" || !got.PreviousSecretExpiresAt.IsZero() {
			t.Errorf("secret material left on a public client: %+v", got)
		}
	})

	t.Run("public to confidential clears the pair", func(t *testing.T) {
		t.Parallel()
		f, created := seeded(t, "none")
		resp := put(t, f, created, map[string]any{
			"redirect_uris":              []string{callback},
			"token_endpoint_auth_method": "client_secret_basic",
		})
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			raw, _ := io.ReadAll(resp.Body)
			t.Fatalf("status=%d want 200 body=%s", resp.StatusCode, raw)
		}
		got, err := f.prov.Store.GetClient(context.Background(), created.clientID)
		if err != nil {
			t.Fatalf("GetClient: %v", err)
		}
		if got.SecretHash == "" {
			t.Error("a newly confidential client must carry a minted secret")
		}
		if got.PreviousSecretHash != "" || !got.PreviousSecretExpiresAt.IsZero() {
			t.Errorf("stale previous pair survived: hash=%q expires=%v",
				got.PreviousSecretHash, got.PreviousSecretExpiresAt)
		}
	})

	t.Run("previous secret in the body is refused", func(t *testing.T) {
		t.Parallel()
		f, created := seeded(t, "client_secret_basic")
		resp := put(t, f, created, map[string]any{
			"redirect_uris":              []string{callback},
			"token_endpoint_auth_method": "client_secret_basic",
			"client_name":                "must not apply",
			"client_secret":              previousSecret,
		})
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			t.Fatal("PUT accepted the previous secret as client_secret")
		}
		got, err := f.prov.Store.GetClient(context.Background(), created.clientID)
		if err != nil {
			t.Fatalf("GetClient: %v", err)
		}
		if got.ClientName == "must not apply" {
			t.Error("a refused update was applied")
		}
	})
}

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
	f := newFixture(t, op.DynamicRegistration{})
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
