package tokenendpoint_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// strictFixture builds a fixture whose Provider was constructed with
// op.WithStrictOfflineAccess() so the strict-mode gate is active. The
// helper exists because the suite-default newFixture wires the lax
// reading; ADR 0017's strict-mode tests need to drive the same
// endpoints with one extra option.
func strictFixture(tb testing.TB) *fixture {
	tb.Helper()
	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	prov := testkit.NewProvider(tb,
		testkit.WithClock(clock),
		testkit.WithOptions(op.WithStrictOfflineAccess()),
	)
	return &fixture{
		prov:     prov,
		endpoint: prov.Server.URL + "/oidc/token",
		clock:    clock,
	}
}

// strictConfidentialClient seeds a confidential client that lists
// refresh_token in its grant types so the gate is exercised on the
// scope axis (and not silently rejected by the per-client grant
// allowlist). The helper mirrors confidentialClientFixture but adds
// an explicit GrantTypes override.
func strictConfidentialClient(tb testing.TB, f *fixture) (*store.Client, string) {
	tb.Helper()
	const secret = "shh-its-a-secret"
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		tb.Fatalf("Argon2id.Hash: %v", err)
	}
	client := f.prov.RegisterClient(tb, testkit.ClientFixture{
		ID:                      "client-strict",
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
	})
	return client, secret
}

// TestStrictOfflineAccess_RefreshExchangeRejectsNonOfflineToken pins
// the §"Error handling" row in ADR 0017: under WithStrictOfflineAccess,
// a refresh request whose originating grant did NOT carry
// "offline_access" fails with invalid_grant on first use, even though
// the bound scope still contains "openid". The exchanger consumes the
// token before the gate fires, so the rejection is single-shot and
// the chain breaks at this point. The error description names the
// policy so an operator can correlate the rejection with the option
// flip.
func TestStrictOfflineAccess_RefreshExchangeRejectsNonOfflineToken(t *testing.T) {
	t.Parallel()

	f := strictFixture(t)
	client, secret := strictConfidentialClient(t, f)
	const tokenID = "rt-pre-flag" //nolint:gosec // opaque test fixture id, not a credential.
	f.seedGrant(t, &store.Grant{
		ID: "grant-pre-flag", Subject: "user-1", ClientID: client.ID,
		Scope: []string{"openid", "email"},
	})
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:       tokenID,
		ClientID: client.ID,
		Subject:  "user-1",
		GrantID:  "grant-pre-flag",
		Scope:    []string{"openid", "email"},
	})

	resp := f.post(t, refreshForm(tokenID, ""), client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400, body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	if got := body["error"]; got != "invalid_grant" {
		t.Errorf("error=%v want invalid_grant", got)
	}
	if desc, _ := body["error_description"].(string); desc == "" ||
		!containsString(desc, "offline_access") {
		t.Errorf("error_description=%q must mention offline_access", desc)
	}
}

// TestStrictOfflineAccess_RefreshExchangeAcceptsOfflineToken is the
// positive companion. A token whose originating grant DID carry
// "offline_access" rotates as usual; the strict-mode gate is a no-op
// for offline-access chains.
func TestStrictOfflineAccess_RefreshExchangeAcceptsOfflineToken(t *testing.T) {
	t.Parallel()

	f := strictFixture(t)
	client, secret := strictConfidentialClient(t, f)
	const tokenID = "rt-offline" //nolint:gosec // opaque test fixture id, not a credential.
	f.seedGrant(t, &store.Grant{
		ID: "grant-offline", Subject: "user-1", ClientID: client.ID,
		Scope: []string{"openid", "offline_access"},
	})
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:       tokenID,
		ClientID: client.ID,
		Subject:  "user-1",
		GrantID:  "grant-offline",
		Scope:    []string{"openid", "offline_access"},
	})

	resp := f.post(t, refreshForm(tokenID, ""), client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200, body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	if got := body["error"]; got != nil {
		t.Errorf("error=%v want nil", got)
	}
	if rotated, _ := body["refresh_token"].(string); rotated == "" {
		t.Errorf("refresh_token must be rotated for offline-access chain")
	}
}

// TestLaxOfflineAccess_RefreshExchangeAcceptsNonOfflineToken pins the
// historical default. With WithStrictOfflineAccess absent (the lax
// reading), a token whose grant did not carry offline_access still
// rotates — that is the library's documented "scope governs UX, not
// gate" posture for OIDC Core 1.0 §11. This is the regression guard
// that prevents a future change from silently flipping the default.
func TestLaxOfflineAccess_RefreshExchangeAcceptsNonOfflineToken(t *testing.T) {
	t.Parallel()

	f := newFixture(t) // lax mode by default.
	client, secret := f.confidentialClientFixture(t)
	const tokenID = "rt-lax" //nolint:gosec // opaque test fixture id, not a credential.
	f.seedGrant(t, &store.Grant{
		ID: "grant-lax", Subject: "user-1", ClientID: client.ID,
		Scope: []string{"openid", "email"},
	})
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:       tokenID,
		ClientID: client.ID,
		Subject:  "user-1",
		GrantID:  "grant-lax",
		Scope:    []string{"openid", "email"},
	})

	resp := f.post(t, refreshForm(tokenID, ""), client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200 (lax default), body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
}

// TestRefreshTokenOfflineTTL_AppliesToOfflineChain pins the TTL
// bucket-selection rule. When WithRefreshTokenOfflineTTL is set and
// the rotated chain carries "offline_access", the rotated token's
// ExpiresAt sits in the offline bucket; without "offline_access" the
// bucket falls back to the default TTL.
func TestRefreshTokenOfflineTTL_AppliesToOfflineChain(t *testing.T) {
	t.Parallel()

	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	prov := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(
			op.WithRefreshTokenTTL(30*24*time.Hour),
			op.WithRefreshTokenOfflineTTL(90*24*time.Hour),
		),
	)
	f := &fixture{
		prov:     prov,
		endpoint: prov.Server.URL + "/oidc/token",
		clock:    clock,
	}
	client, secret := f.confidentialClientFixture(t)

	const tokenID = "rt-offline-ttl" //nolint:gosec // opaque test fixture id, not a credential.
	f.seedGrant(t, &store.Grant{
		ID: "grant-offline-ttl", Subject: "user-1", ClientID: client.ID,
		Scope: []string{"openid", "offline_access"},
	})
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:       tokenID,
		ClientID: client.ID,
		Subject:  "user-1",
		GrantID:  "grant-offline-ttl",
		Scope:    []string{"openid", "offline_access"},
	})

	resp := f.post(t, refreshForm(tokenID, ""), client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200, body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	rotated, _ := body["refresh_token"].(string)
	if rotated == "" {
		t.Fatal("refresh_token must be rotated")
	}
	rec, err := prov.Store.RefreshTokens().Find(context.Background(), rotated)
	if err != nil || rec == nil {
		t.Fatalf("Find(%q): rec=%v err=%v", rotated, rec, err)
	}
	expected := clock.now.Add(90 * 24 * time.Hour)
	if got := rec.ExpiresAt; got.Sub(expected).Abs() > time.Second {
		t.Errorf("rotated ExpiresAt=%v want ~%v (offline bucket)", got, expected)
	}
}

// containsString avoids pulling in the strings package's import noise
// for the single substring check this file makes.
func containsString(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
