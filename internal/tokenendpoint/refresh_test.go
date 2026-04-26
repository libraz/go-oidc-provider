package tokenendpoint_test

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/libraz/go-oidc-provider/op/store"
)

// refreshForm builds the canonical refresh_token form body. scope is
// optional; an empty string omits the parameter.
func refreshForm(token, scope string) url.Values {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", token)
	if scope != "" {
		form.Set("scope", scope)
	}
	return form
}

// TestRefresh_HappyPath_OIDC seeds an OIDC refresh token and exchanges
// it. The response must rotate the refresh token, mint a new id_token,
// and echo the original scope.
func TestRefresh_HappyPath_OIDC(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)
	const tokenID = "rt-happy"
	const subject = "user-1"
	const grantID = "grant-rt"

	f.seedGrant(t, &store.Grant{
		ID: grantID, Subject: subject, ClientID: client.ID,
		Scope: []string{"openid", "email"},
	})
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:       tokenID,
		ClientID: client.ID,
		Subject:  subject,
		GrantID:  grantID,
		Scope:    []string{"openid", "email"},
	})

	resp := f.post(t, refreshForm(tokenID, ""), client.ID, secret)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200, body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	rotated, _ := body["refresh_token"].(string)
	if rotated == "" || rotated == tokenID {
		t.Errorf("refresh_token must be rotated; got %q (input %q)", rotated, tokenID)
	}
	if _, hasID := body["id_token"]; !hasID {
		t.Errorf("id_token must be issued for openid-scoped refresh")
	}
	if got := body["scope"]; got != "openid email" {
		t.Errorf("scope=%v want openid email", got)
	}
}

// TestRefresh_HappyPath_NonOIDC verifies that a refresh whose original
// grant did not carry "openid" produces no id_token.
func TestRefresh_HappyPath_NonOIDC(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)
	const tokenID = "rt-nooidc" //nolint:gosec // not a credential — opaque test fixture id.
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:       tokenID,
		ClientID: client.ID,
		Subject:  "user-1",
		GrantID:  "grant-nooidc",
		Scope:    []string{"profile"},
	})

	resp := f.post(t, refreshForm(tokenID, ""), client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	body := decodeJSON(t, resp)
	if _, hasID := body["id_token"]; hasID {
		t.Errorf("id_token must NOT be issued without openid scope")
	}
}

// TestRefresh_Replay verifies that re-using an already-consumed
// refresh token surfaces invalid_grant AND that the freshly-rotated
// refresh token is also revoked (chain-wide replay defence).
func TestRefresh_Replay(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)
	const tokenID = "rt-replay"
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:       tokenID,
		ClientID: client.ID,
		Subject:  "user-1",
		GrantID:  "grant-replay",
		Scope:    []string{"openid"},
	})

	// First exchange must succeed.
	first := f.post(t, refreshForm(tokenID, ""), client.ID, secret)
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first exchange status=%d want 200", first.StatusCode)
	}
	body := decodeJSON(t, first)
	first.Body.Close()
	rotated, _ := body["refresh_token"].(string)
	if rotated == "" {
		t.Fatal("first exchange did not return a rotated refresh token")
	}

	// Replay of the original token must fail and revoke the chain.
	second := f.post(t, refreshForm(tokenID, ""), client.ID, secret)
	defer second.Body.Close()
	if second.StatusCode != http.StatusBadRequest {
		t.Fatalf("replay status=%d want 400", second.StatusCode)
	}
	if got := decodeJSON(t, second); got["error"] != "invalid_grant" {
		t.Errorf("error=%v want invalid_grant", got["error"])
	}

	// The freshly-rotated refresh token MUST also fail because the
	// chain-wide revocation walked the descendants.
	third := f.post(t, refreshForm(rotated, ""), client.ID, secret)
	defer third.Body.Close()
	if third.StatusCode != http.StatusBadRequest {
		t.Fatalf("post-revoke status=%d want 400", third.StatusCode)
	}
	if got := decodeJSON(t, third); got["error"] != "invalid_grant" {
		t.Errorf("post-revoke error=%v want invalid_grant", got["error"])
	}
}

// TestRefresh_ScopeWidening enforces RFC 6749 §6.
func TestRefresh_ScopeWidening(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)
	const tokenID = "rt-widen"
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:       tokenID,
		ClientID: client.ID,
		Subject:  "user-1",
		GrantID:  "grant-widen",
		Scope:    []string{"openid"},
	})

	resp := f.post(t, refreshForm(tokenID, "openid email"), client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	if got := decodeJSON(t, resp); got["error"] != "invalid_scope" {
		t.Errorf("error=%v want invalid_scope", got["error"])
	}
}

// TestRefresh_ScopeNarrowing returns 200 with the narrowed scope echoed
// back to the caller.
func TestRefresh_ScopeNarrowing(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)
	const tokenID = "rt-narrow"
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:       tokenID,
		ClientID: client.ID,
		Subject:  "user-1",
		GrantID:  "grant-narrow",
		Scope:    []string{"openid", "email", "profile"},
	})

	resp := f.post(t, refreshForm(tokenID, "openid"), client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	body := decodeJSON(t, resp)
	if got := body["scope"]; got != "openid" {
		t.Errorf("scope=%v want openid", got)
	}
}

// TestRefresh_MissingToken yields invalid_request when the body omits
// refresh_token.
func TestRefresh_MissingToken(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	resp := f.post(t, form, client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	if got := decodeJSON(t, resp); got["error"] != "invalid_request" {
		t.Errorf("error=%v want invalid_request", got["error"])
	}
}
