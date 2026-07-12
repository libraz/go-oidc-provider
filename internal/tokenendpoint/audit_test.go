package tokenendpoint_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/audit"
	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// auditCapture wraps a slog logger that emits audit events as JSON
// records into a bytes.Buffer. Tests that assert on emitted audit
// events build a Provider through this capture so the wire layout
// observed by an embedder's slog handler is what the test sees.
type auditCapture struct {
	buf *bytes.Buffer
}

func newAuditCapture() *auditCapture {
	return &auditCapture{buf: &bytes.Buffer{}}
}

func (c *auditCapture) logger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(c.buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
}

// findEvent returns the first audit record whose "event" attribute
// matches name, or nil when none is present. The decoder pre-filters
// non-audit lines by the "audit"="true" sentinel so unrelated info
// records (e.g. discovery boot) do not pollute the assertion.
func (c *auditCapture) findEvent(t *testing.T, name string) map[string]any {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(c.buf.String()))
	for dec.More() {
		var rec map[string]any
		if err := dec.Decode(&rec); err != nil {
			t.Fatalf("decode audit line: %v", err)
		}
		if rec["audit"] != "true" {
			continue
		}
		if rec["event"] == name {
			return rec
		}
	}
	return nil
}

// auditFixture builds a fixture whose Provider is wired with an
// audit logger that captures every emitted event into the returned
// auditCapture. Mirrors strictFixture's shape (custom WithOptions
// surface) so test bodies stay readable.
func auditFixture(tb testing.TB) (*fixture, *auditCapture) {
	tb.Helper()
	capture := newAuditCapture()
	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	prov := testkit.NewProvider(tb,
		testkit.WithClock(clock),
		testkit.WithOptions(op.WithAuditLogger(capture.logger())),
	)
	return &fixture{
		prov:     prov,
		endpoint: prov.Server.URL + "/oidc/token",
		clock:    clock,
	}, capture
}

// auditOfflineFixture wires the audit-capturing fixture together with
// an offline-specific TTL so the "ttl_bucket=offline" branch is
// reachable without redefining the fixture for every test.
func auditOfflineFixture(tb testing.TB) (*fixture, *auditCapture) {
	tb.Helper()
	capture := newAuditCapture()
	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	prov := testkit.NewProvider(tb,
		testkit.WithClock(clock),
		testkit.WithOptions(
			op.WithAuditLogger(capture.logger()),
			op.WithRefreshTokenOfflineTTL(72*time.Hour),
		),
	)
	return &fixture{
		prov:     prov,
		endpoint: prov.Server.URL + "/oidc/token",
		clock:    clock,
	}, capture
}

// auditRefreshClient seeds a confidential client that lists
// refresh_token in its grant types so the issuance gate fires.
func auditRefreshClient(tb testing.TB, f *fixture) (*store.Client, string) {
	tb.Helper()
	const secret = "shh-its-a-secret"
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		tb.Fatalf("Argon2id.Hash: %v", err)
	}
	client := f.prov.RegisterClient(tb, testkit.ClientFixture{
		ID:                      "client-audit",
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
	})
	return client, secret
}

// TestAudit_ClientAuthnFailure_BadSecret pins the failure-side
// audit event: a /token POST whose Basic-auth header carries the
// right client_id but the wrong secret MUST collapse to 401
// invalid_client AND emit a single "client_authn.failure" audit
// event carrying the failing client_id, the parsed auth method, and
// an "invalid_client_credentials" reason code.
//
// Spec: RFC 6749 §5.2.
func TestAudit_ClientAuthnFailure_BadSecret(t *testing.T) {
	t.Parallel()

	f, capture := auditFixture(t)
	client, _ := auditRefreshClient(t, f)

	form := url.Values{
		"grant_type": {"refresh_token"},
		"refresh_token": {
			"opaque-token-the-rotation-path-never-sees-because-auth-fails-first",
		},
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		f.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(client.ID, "wrong-secret")
	resp, err := f.prov.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d want 401", resp.StatusCode)
	}

	rec := capture.findEvent(t, "client_authn.failure")
	if rec == nil {
		t.Fatalf("client_authn.failure not emitted; capture=%s", capture.buf.String())
	}
	if got := rec["client_id"]; got != client.ID {
		t.Errorf("client_id=%v want %q", got, client.ID)
	}
	extras, _ := rec["extras"].(map[string]any)
	if extras == nil {
		t.Fatalf("extras missing on client_authn.failure: %v", rec)
	}
	if got := extras["reason"]; got != "invalid_client_credentials" {
		t.Errorf("extras.reason=%v want invalid_client_credentials", got)
	}
	if got := extras["method"]; got != "client_secret_basic" {
		t.Errorf("extras.method=%v want client_secret_basic", got)
	}
}

// TestAudit_TokenIssued_LaxDefaultIssuesRefreshWithoutOfflineAccess
// pins the lax reading of OIDC Core 1.0 §11 (the historical default):
// an authcode exchange whose granted scope contains "openid" but not
// "offline_access" still issues a refresh token to a refresh-capable
// client, and therefore emits the "token.issued" audit event with
// extras.offline_access=false. Strict-mode issuance is exercised
// separately via op.WithStrictOfflineAccess.
func TestAudit_TokenIssued_LaxDefaultIssuesRefreshWithoutOfflineAccess(t *testing.T) {
	t.Parallel()

	f, capture := auditFixture(t)
	client, secret := auditRefreshClient(t, f)
	verifier, challenge := pkcePair()
	const codeID = "code-audit"
	const grantID = "grant-audit"
	const subject = "user-1"
	redirect := client.RedirectURIs[0]

	f.seedGrant(t, &store.Grant{
		ID: grantID, Subject: subject, ClientID: client.ID,
		Scope: []string{"openid"},
	})
	f.seedAuthCode(t, &store.AuthorizationCode{
		ID:                  codeID,
		ClientID:            client.ID,
		Subject:             subject,
		GrantID:             grantID,
		RedirectURI:         redirect,
		Scope:               []string{"openid"},
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	})

	resp := f.post(t, authCodeForm(codeID, redirect, verifier), client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}

	rec := capture.findEvent(t, "token.issued")
	if rec == nil {
		t.Fatalf("token.issued not emitted under lax default; capture=%s", capture.buf.String())
	}
	extras, _ := rec["extras"].(map[string]any)
	if extras == nil {
		t.Fatalf("extras missing on token.issued: %v", rec)
	}
	if got := extras["offline_access"]; got != false {
		t.Errorf("extras.offline_access=%v want false", got)
	}
}

func TestAudit_CodeConsumed_OnAuthCodeExchange(t *testing.T) {
	t.Parallel()

	f, capture := auditFixture(t)
	client, secret := auditRefreshClient(t, f)
	verifier, challenge := pkcePair()
	const codeID = "code-consumed-audit"
	const grantID = "grant-consumed-audit"
	const subject = "user-1"
	redirect := client.RedirectURIs[0]

	f.seedGrant(t, &store.Grant{
		ID: grantID, Subject: subject, ClientID: client.ID,
		Scope: []string{"openid"},
	})
	f.seedAuthCode(t, &store.AuthorizationCode{
		ID:                  codeID,
		ClientID:            client.ID,
		Subject:             subject,
		GrantID:             grantID,
		RedirectURI:         redirect,
		Scope:               []string{"openid"},
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	})

	resp := f.post(t, authCodeForm(codeID, redirect, verifier), client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}

	rec := capture.findEvent(t, "code.consumed")
	if rec == nil {
		t.Fatalf("code.consumed not emitted; capture=%s", capture.buf.String())
	}
	if rec["actor_id"] != subject {
		t.Errorf("actor_id=%v want %s", rec["actor_id"], subject)
	}
	if rec["client_id"] != client.ID {
		t.Errorf("client_id=%v want %s", rec["client_id"], client.ID)
	}
	extras, _ := rec["extras"].(map[string]any)
	if extras == nil {
		t.Fatalf("extras missing on code.consumed: %v", rec)
	}
	wantCodeFingerprint := audit.Fingerprint(codeID)
	if got := extras["code_id"]; got != wantCodeFingerprint {
		t.Errorf("extras.code_id=%v want %s", got, wantCodeFingerprint)
	}
	if got, ok := extras["code_id"].(string); !ok || got == codeID {
		t.Errorf("extras.code_id=%v must not equal the raw code %s", extras["code_id"], codeID)
	}
	if got := extras["grant_id"]; got != grantID {
		t.Errorf("extras.grant_id=%v want %s", got, grantID)
	}
	if _, ok := extras["consumed_at"]; !ok {
		t.Errorf("extras.consumed_at missing: %v", extras)
	}
}

// TestAudit_TokenIssued_OfflineAccessFlag pins the offline_access=
// true branch: when the granted scope contains "offline_access" AND
// op.WithRefreshTokenOfflineTTL is configured, the audit event
// reports the long-lived bucket so SOC dashboards can distinguish
// stay-signed-in chains from conventional rotation.
func TestAudit_TokenIssued_OfflineAccessFlag(t *testing.T) {
	t.Parallel()

	f, capture := auditOfflineFixture(t)
	client, secret := auditRefreshClient(t, f)
	verifier, challenge := pkcePair()
	const codeID = "code-audit-offline"
	const grantID = "grant-audit-offline"
	const subject = "user-1"
	redirect := client.RedirectURIs[0]

	f.seedGrant(t, &store.Grant{
		ID: grantID, Subject: subject, ClientID: client.ID,
		Scope: []string{"openid", "offline_access"},
	})
	f.seedAuthCode(t, &store.AuthorizationCode{
		ID:                  codeID,
		ClientID:            client.ID,
		Subject:             subject,
		GrantID:             grantID,
		RedirectURI:         redirect,
		Scope:               []string{"openid", "offline_access"},
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	})

	resp := f.post(t, authCodeForm(codeID, redirect, verifier), client.ID, secret)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}

	rec := capture.findEvent(t, "token.issued")
	if rec == nil {
		t.Fatalf("token.issued not emitted; capture=%s", capture.buf.String())
	}
	extras, _ := rec["extras"].(map[string]any)
	if extras == nil {
		t.Fatalf("extras missing on token.issued: %v", rec)
	}
	if got := extras["offline_access"]; got != true {
		t.Errorf("extras.offline_access=%v want true", got)
	}
	if got := extras["ttl_bucket"]; got != "offline" {
		t.Errorf("extras.ttl_bucket=%v want offline", got)
	}
}

// TestAudit_TokenRefreshed_OnRotation pins the
// "audit.token.refreshed" emission produced by the rotation path.
// The seeded refresh token rides with the offline_access scope so
// the extras carry offline_access=true; a non-offline rotation is
// covered by the parallel TestAudit_TokenRefreshed_DefaultBucket.
func TestAudit_TokenRefreshed_OnRotation(t *testing.T) {
	t.Parallel()

	f, capture := auditOfflineFixture(t)
	client, secret := auditRefreshClient(t, f)
	const tokenID = "rt-rotated"
	const grantID = "grant-audit-rotated"
	const subject = "user-1"

	f.seedGrant(t, &store.Grant{
		ID: grantID, Subject: subject, ClientID: client.ID,
		Scope: []string{"openid", "offline_access"},
	})
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
		t.Fatalf("status=%d want 200, body=%v", resp.StatusCode, decodeJSON(t, resp))
	}

	rec := capture.findEvent(t, "token.refreshed")
	if rec == nil {
		t.Fatalf("token.refreshed not emitted; capture=%s", capture.buf.String())
	}
	if rec["actor_id"] != subject {
		t.Errorf("actor_id=%v want %s", rec["actor_id"], subject)
	}
	if rec["client_id"] != client.ID {
		t.Errorf("client_id=%v want %s", rec["client_id"], client.ID)
	}
	extras, _ := rec["extras"].(map[string]any)
	if extras == nil {
		t.Fatalf("extras missing on token.refreshed: %v", rec)
	}
	if got := extras["offline_access"]; got != true {
		t.Errorf("extras.offline_access=%v want true", got)
	}
	if got := extras["ttl_bucket"]; got != "offline" {
		t.Errorf("extras.ttl_bucket=%v want offline", got)
	}
	if got := extras["grant_id"]; got != grantID {
		t.Errorf("extras.grant_id=%v want %s", got, grantID)
	}
}

// TestAudit_TokenRefreshed_DefaultBucket pins the conventional
// rotation path where offline_access is absent: the audit extras
// MUST carry ttl_bucket="default" and offline_access=false so SOC
// queries grouping by bucket land on the right counter.
func TestAudit_TokenRefreshed_DefaultBucket(t *testing.T) {
	t.Parallel()

	f, capture := auditFixture(t)
	client, secret := auditRefreshClient(t, f)
	const tokenID = "rt-default"
	const grantID = "grant-audit-default"
	const subject = "user-1"

	f.seedGrant(t, &store.Grant{
		ID: grantID, Subject: subject, ClientID: client.ID,
		Scope: []string{"openid"},
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

	rec := capture.findEvent(t, "token.refreshed")
	if rec == nil {
		t.Fatalf("token.refreshed not emitted; capture=%s", capture.buf.String())
	}
	extras, _ := rec["extras"].(map[string]any)
	if extras == nil {
		t.Fatalf("extras missing on token.refreshed: %v", rec)
	}
	if got := extras["offline_access"]; got != false {
		t.Errorf("extras.offline_access=%v want false", got)
	}
	if got := extras["ttl_bucket"]; got != "default" {
		t.Errorf("extras.ttl_bucket=%v want default", got)
	}
}
