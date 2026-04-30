package tokenendpoint_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
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

func TestRefresh_RequireAuthTime_EmitsAuthTime(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)
	client.RequireAuthTime = true
	if err := f.prov.Store.UpdateClient(context.Background(), client); err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}
	const tokenID = "rt-require-auth-time"
	const subject = "user-1"
	const grantID = "grant-rt-require-auth-time"
	authTime := f.clock.now.Add(-3 * time.Minute)

	if err := f.prov.Store.Grants().Save(context.Background(), &store.Grant{
		ID:        grantID,
		Subject:   subject,
		ClientID:  client.ID,
		Scope:     []string{"openid", "offline_access"},
		AuthTime:  authTime,
		CreatedAt: f.clock.now,
		UpdatedAt: f.clock.now,
	}); err != nil {
		t.Fatalf("Grants.Save: %v", err)
	}
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:       tokenID,
		ClientID: client.ID,
		Subject:  subject,
		GrantID:  grantID,
		Scope:    []string{"openid", "offline_access"},
	})

	resp := f.post(t, refreshForm(tokenID, ""), client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200 body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	idt, _ := body["id_token"].(string)
	if idt == "" {
		t.Fatal("id_token missing")
	}
	idClaims := decodeIDTokenClaims(t, idt)
	if got := idClaims["auth_time"]; got != float64(authTime.Unix()) {
		t.Fatalf("auth_time=%v want %d", got, authTime.Unix())
	}
}

func TestRefresh_RequireAuthTime_MissingAuthTimeFails(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)
	client.RequireAuthTime = true
	if err := f.prov.Store.UpdateClient(context.Background(), client); err != nil {
		t.Fatalf("UpdateClient: %v", err)
	}
	const tokenID = "rt-require-auth-time-missing"
	const subject = "user-1"
	const grantID = "grant-rt-require-auth-time-missing"

	if err := f.prov.Store.Grants().Save(context.Background(), &store.Grant{
		ID:       grantID,
		Subject:  subject,
		ClientID: client.ID,
		Scope:    []string{"openid", "offline_access"},
	}); err != nil {
		t.Fatalf("Grants.Save: %v", err)
	}
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:       tokenID,
		ClientID: client.ID,
		Subject:  subject,
		GrantID:  grantID,
		Scope:    []string{"openid", "offline_access"},
	})

	resp := f.post(t, refreshForm(tokenID, ""), client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status=%d want 500 body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	if got := body["error"]; got != "server_error" {
		t.Fatalf("error=%v want server_error", got)
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

// movableClock advances by mutating a shared time.Time so the OP and
// the test see the same wall-clock readings even after the test has
// stepped forward.
type movableClock struct{ cur *time.Time }

func (c movableClock) Now() time.Time { return *c.cur }

// TestRefresh_Replay verifies that, once the RFC 9700 §2.2.2 grace
// window has elapsed, re-using an already-consumed refresh token
// surfaces invalid_grant AND chain-wide replay defence revokes every
// descendant. The grace path itself is covered by
// TestRefresh_GraceWindow below.
func TestRefresh_Replay(t *testing.T) {
	t.Parallel()

	cur := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	prov := testkit.NewProvider(t, testkit.WithClock(movableClock{cur: &cur}))
	f := &fixture{
		prov:     prov,
		endpoint: prov.Server.URL + "/oidc/token",
		clock:    fixedClock{now: cur},
	}
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

	// Step well past the default 30-second grace window so the second
	// presentation falls onto the strict replay path.
	cur = cur.Add(2 * time.Minute)

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

// TestRefresh_GraceWindow exercises the RFC 9700 §2.2.2 grace path
// end-to-end at the HTTP layer: a refresh token presented again
// within the configured window returns 200 OK, a fresh access_token,
// and (importantly) NO new refresh_token field — the canonical
// successor was already issued on the first exchange.
func TestRefresh_GraceWindow(t *testing.T) {
	t.Parallel()

	cur := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	prov := testkit.NewProvider(t, testkit.WithClock(movableClock{cur: &cur}))
	f := &fixture{
		prov:     prov,
		endpoint: prov.Server.URL + "/oidc/token",
		clock:    fixedClock{now: cur},
	}
	client, secret := f.confidentialClientFixture(t)
	const tokenID = "rt-grace"
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:       tokenID,
		ClientID: client.ID,
		Subject:  "user-1",
		GrantID:  "grant-grace",
		Scope:    []string{"openid"},
	})

	first := f.post(t, refreshForm(tokenID, ""), client.ID, secret)
	if first.StatusCode != http.StatusOK {
		t.Fatalf("first status=%d want 200", first.StatusCode)
	}
	firstBody := decodeJSON(t, first)
	first.Body.Close()
	firstAccess, _ := firstBody["access_token"].(string)
	if firstAccess == "" {
		t.Fatal("first response missing access_token")
	}
	if rt, _ := firstBody["refresh_token"].(string); rt == "" {
		t.Fatal("first response must rotate a refresh token")
	}

	// Step inside the grace window (default 30s).
	cur = cur.Add(5 * time.Second)

	second := f.post(t, refreshForm(tokenID, ""), client.ID, secret)
	defer second.Body.Close()
	if second.StatusCode != http.StatusOK {
		t.Fatalf("grace status=%d want 200", second.StatusCode)
	}
	secondBody := decodeJSON(t, second)
	if rt, ok := secondBody["refresh_token"]; ok {
		t.Errorf("grace response must omit refresh_token; got %v", rt)
	}
	if got, _ := secondBody["access_token"].(string); got == "" {
		t.Error("grace response must include a fresh access_token")
	} else if got == firstAccess {
		t.Error("grace response must mint a NEW access_token (RFC 9700 §2.2.2)")
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

// scopedFixture builds a fresh fixture whose op.Provider has a custom
// scope registered with an AllowedClients allowlist that excludes the
// confidential test client. The lookup is plumbed through op.New →
// scoperegistry.New → tokenendpoint.Deps.Scopes; this exercises the
// full wire-up rather than the ExchangerConfig in isolation.
func scopedFixture(tb testing.TB) *fixture {
	tb.Helper()
	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	prov := testkit.NewProvider(tb,
		testkit.WithClock(clock),
		testkit.WithOptions(op.WithScope(op.Scope{
			Name:           "billing:write",
			Public:         true,
			AllowedClients: []string{"svc-billing"},
		})),
	)
	return &fixture{
		prov:     prov,
		endpoint: prov.Server.URL + "/oidc/token",
		clock:    clock,
	}
}

// TestRefresh_ScopeAllowedClients_Rejected verifies that the
// /token endpoint enforces the AllowedClients allowlist. The
// confidential client requests a scope locked to a different client and
// MUST be rejected with invalid_scope before the refresh token is
// consumed.
func TestRefresh_ScopeAllowedClients_Rejected(t *testing.T) {
	t.Parallel()

	f := scopedFixture(t)
	const secret = "shh-its-a-secret"
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	client := f.prov.RegisterClient(t, testkit.ClientFixture{
		ID:                      "client-conf",
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
		Scopes:                  []string{"openid", "profile", "email", "billing:write"},
	})

	const tokenID = "rt-allowlist"
	f.seedGrant(t, &store.Grant{
		ID: "grant-allowlist", Subject: "user-1", ClientID: client.ID,
		Scope: []string{"openid", "billing:write"},
	})
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:       tokenID,
		ClientID: client.ID,
		Subject:  "user-1",
		GrantID:  "grant-allowlist",
		Scope:    []string{"openid", "billing:write"},
	})

	resp := f.post(t, refreshForm(tokenID, "openid billing:write"), client.ID, secret)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", resp.StatusCode)
	}
	body := decodeJSON(t, resp)
	if got := body["error"]; got != "invalid_scope" {
		t.Errorf("error=%v want invalid_scope", got)
	}

	// The presented refresh token MUST still be intact: the allowlist
	// check runs before refresh.Exchanger.Exchange, so the record's
	// ConsumedAt should remain nil and a subsequent allowlist-clean
	// request must succeed against the same token.
	rec, err := f.prov.Store.RefreshTokens().Find(context.Background(), tokenID)
	if err != nil {
		t.Fatalf("RefreshTokens.Find after rejection: %v", err)
	}
	if rec.ConsumedAt != nil {
		t.Fatalf("refresh token must not be consumed on allowlist rejection (ConsumedAt=%v)", rec.ConsumedAt)
	}

	// Without a scope override the request reuses the bound scope and
	// should succeed (the allowlist check is skipped because the
	// request did not ask for a fresh override). This double-checks
	// that the rejection above did not corrupt the chain.
	follow := f.post(t, refreshForm(tokenID, ""), client.ID, secret)
	defer follow.Body.Close()
	if follow.StatusCode != http.StatusOK {
		t.Fatalf("follow-up status=%d want 200; allowlist rejection must leave the token usable", follow.StatusCode)
	}
}

// TestRefresh_ScopeAllowedClients_Permitted is the positive
// counterpart: the same registry, but the requesting client is on the
// allowlist. The refresh succeeds and the rotated token is returned.
func TestRefresh_ScopeAllowedClients_Permitted(t *testing.T) {
	t.Parallel()

	f := scopedFixture(t)
	const secret = "shh-its-a-secret"
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	client := f.prov.RegisterClient(t, testkit.ClientFixture{
		ID:                      "svc-billing",
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
		Scopes:                  []string{"openid", "billing:write"},
	})

	const tokenID = "rt-allowlist-ok" //nolint:gosec // not a credential — opaque test fixture id.
	f.seedGrant(t, &store.Grant{
		ID: "grant-allowlist-ok", Subject: "user-1", ClientID: client.ID,
		Scope: []string{"openid", "billing:write"},
	})
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:       tokenID,
		ClientID: client.ID,
		Subject:  "user-1",
		GrantID:  "grant-allowlist-ok",
		Scope:    []string{"openid", "billing:write"},
	})

	resp := f.post(t, refreshForm(tokenID, "openid billing:write"), client.ID, secret)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200, body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	if got, _ := body["refresh_token"].(string); got == "" {
		t.Errorf("refresh_token must rotate on allowlist-permitted refresh: %v", body)
	}
}

// Note: authorization_code grant does not accept a scope reduction at
// /token (the granted scope is bound to the issued code at /authorize).
// The AllowedClients allowlist is therefore enforced upstream by the
// authorize endpoint; no /token-side authcode test is required for
// allowlist coverage.

// TestRefresh_HonoursClaimsRequest_IDToken verifies that an OIDC Core
// 1.0 §5.5 "claims" request payload persisted on the originating grant
// is honoured by the refresh-derived id_token. The grant carries an
// id_token request for "email"; the user store has the matching value;
// the refreshed id_token MUST surface the claim. Without the projector
// wired through the refresh path the claim was silently dropped.
func TestRefresh_HonoursClaimsRequest_IDToken(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	client, secret := f.confidentialClientFixture(t)
	const tokenID = "rt-claims"
	const subject = "user-claims"
	const grantID = "grant-claims"

	f.prov.Store.PutUser(context.Background(), &store.User{
		Subject: subject,
		Claims:  map[string]any{"email": "user@example.com"},
	})
	f.seedGrant(t, &store.Grant{
		ID: grantID, Subject: subject, ClientID: client.ID,
		Scope: []string{"openid"},
		Claims: map[string]any{
			"request": map[string]any{
				"id_token": map[string]any{
					"email": map[string]any{"essential": true},
				},
			},
		},
	})
	f.seedRefreshToken(t, &store.RefreshToken{
		ID:       tokenID,
		ClientID: client.ID,
		Subject:  subject,
		GrantID:  grantID,
		Scope:    []string{"openid"},
	})

	resp := f.post(t, refreshForm(tokenID, ""), client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200, body=%v", resp.StatusCode, decodeJSON(t, resp))
	}
	body := decodeJSON(t, resp)
	idt, _ := body["id_token"].(string)
	if idt == "" {
		t.Fatal("id_token missing")
	}
	idClaims := decodeIDTokenClaims(t, idt)
	if got := idClaims["email"]; got != "user@example.com" {
		t.Errorf("id_token.email=%v want user@example.com (claims request not honoured on refresh path)", got)
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
