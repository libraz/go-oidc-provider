package scenarios_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

// Token-endpoint redemptions look the grant's subject up in the user
// store before minting. A subject the embedder deleted earns
// invalid_grant, and the grant's other credentials die with it.

const (
	sdClientID = "rp-deprovision"
	sdSecret   = "rp-deprovision-secret" //nolint:gosec // test fixture: not a real credential.
	sdCallback = "https://rp.testkit.invalid/callback"
)

// sdUsers decorates the reference user store so a test can delete the
// subject from the embedder's directory after tokens were issued.
type sdUsers struct {
	store.UserStore
	gone atomic.Bool
}

func (u *sdUsers) FindBySubject(ctx context.Context, sub string) (*store.User, error) {
	if u.gone.Load() {
		return nil, store.ErrNotFound
	}
	return u.UserStore.FindBySubject(ctx, sub)
}

// newSDUsers returns a user store holding subjects, and the option that
// makes the OP read it.
func newSDUsers(subjects ...string) (*sdUsers, op.Option) {
	backing := inmem.New()
	for _, s := range subjects {
		backing.PutUser(context.Background(), &store.User{Subject: s})
	}
	users := &sdUsers{UserStore: backing.Users()}
	return users, op.WithUserStore(users)
}

// sdTokenPost POSTs form to /token with the given Basic credentials.
func sdTokenPost(t *testing.T, tk *testkit.Provider, form url.Values, clientID, secret string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("NewRequest /token: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, secret)
	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /token body: %v", err)
	}
	body := map[string]any{}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("decode /token body %q: %v", raw, err)
	}
	return resp.StatusCode, body
}

func sdExpectInvalidGrant(t *testing.T, what string, status int, body map[string]any) {
	t.Helper()
	if status != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Fatalf("%s: status=%d body=%v, want 400 invalid_grant", what, status, body)
	}
	if _, ok := body["access_token"]; ok {
		t.Fatalf("%s: refusal carried an access_token", what)
	}
}

func sdExpectInactive(t *testing.T, tk *testkit.Provider, token, clientID, secret string) {
	t.Helper()
	status, body := postIntrospect(t, tk, token, clientID, secret)
	if status != http.StatusOK {
		t.Fatalf("/introspect status=%d body=%v", status, body)
	}
	if active, _ := body["active"].(bool); active {
		t.Fatalf("access token still active after the grant was torn down: %v", body)
	}
}

func sdRefresh(t *testing.T, tk *testkit.Provider, rt, clientID, secret string) (int, map[string]any) {
	t.Helper()
	return sdTokenPost(t, tk, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}, clientID, secret)
}

type sdCodeEnv struct {
	tk      *testkit.Provider
	users   *sdUsers
	capture *scenariokit.AuditCapture
}

func newSDCodeEnv(t *testing.T) *sdCodeEnv {
	t.Helper()
	users, withUsers := newSDUsers(scenariokit.DefaultSubject)
	capture := scenariokit.NewAuditCapture()
	tk := testkit.NewProvider(t, testkit.WithOptions(
		withUsers,
		op.WithFeature(feature.Introspect),
		op.WithAuditLogger(capture.Logger()),
	))
	hash, err := op.HashClientSecret(sdSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      sdClientID,
		SecretHash:              hash,
		RedirectURIs:            []string{sdCallback},
		Scopes:                  []string{"openid", "profile", "offline_access"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	return &sdCodeEnv{tk: tk, users: users, capture: capture}
}

// code runs an authorization request and returns the code with its
// PKCE verifier.
func (e *sdCodeEnv) code(t *testing.T) (string, string) {
	t.Helper()
	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, e.tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID:    sdClientID,
		RedirectURI: sdCallback,
		Scope:       "openid offline_access",
		PKCE:        pkce,
	})
	if flow.Code == "" {
		t.Fatalf("authorize callback missing code: %+v", flow)
	}
	return flow.Code, pkce.Verifier
}

func (e *sdCodeEnv) exchange(t *testing.T, code, verifier string) scenariokit.TokenResponse {
	t.Helper()
	return scenariokit.ExchangeCode(t, e.tk, scenariokit.ExchangeCodeRequest{
		Code: code, RedirectURI: sdCallback, Verifier: verifier,
		ClientID: sdClientID, ClientSecret: sdSecret,
	})
}

func (e *sdCodeEnv) issue(t *testing.T) scenariokit.TokenResponse {
	t.Helper()
	code, verifier := e.code(t)
	tok := e.exchange(t, code, verifier)
	if tok.StatusCode != http.StatusOK || tok.AccessToken == "" || tok.RefreshToken == "" {
		t.Fatalf("/token status=%d body=%v, want access and refresh tokens", tok.StatusCode, tok.Raw)
	}
	return tok
}

// TestSubjectDeprovisioning_RefreshRefusedAndAccessTokenDead pins that
// once the subject backing a live grant is gone, a refresh redemption
// is refused and the grant's earlier access token reads inactive.
//
// Tracks: CVE-2026-16103 — token redemption skipped the subject's
// disabled/deleted re-check, letting a deprovisioned account's tokens
// keep working. The white-box counterpart of this surface is pinned by
// TestDeprovisionedSubject_RefreshRefusedAndGrantTornDown.
func TestSubjectDeprovisioning_RefreshRefusedAndAccessTokenDead(t *testing.T) {
	t.Parallel()
	env := newSDCodeEnv(t)
	tok := env.issue(t)

	env.users.gone.Store(true)
	status, body := sdRefresh(t, env.tk, tok.RefreshToken, sdClientID, sdSecret)
	sdExpectInvalidGrant(t, "refresh", status, body)
	sdExpectInactive(t, env.tk, tok.AccessToken, sdClientID, sdSecret)

	var refusal bool
	for _, ev := range env.capture.EventsByName(string(op.AuditTokenRevoked)) {
		refusal = refusal || ev.Level == slog.LevelWarn
	}
	if !refusal {
		t.Fatalf("no %s event recorded the refusal", op.AuditTokenRevoked)
	}
}

func TestSubjectDeprovisioning_CodeRefusedAndEarlierTokensDead(t *testing.T) {
	t.Parallel()
	env := newSDCodeEnv(t)
	earlier := env.issue(t)
	code, verifier := env.code(t)

	env.users.gone.Store(true)
	refused := env.exchange(t, code, verifier)
	sdExpectInvalidGrant(t, "authorization_code", refused.StatusCode, refused.Raw)
	sdExpectInactive(t, env.tk, earlier.AccessToken, sdClientID, sdSecret)

	// The earlier refresh token died with the grant: it stays refused
	// once the subject is back.
	env.users.gone.Store(false)
	status, body := sdRefresh(t, env.tk, earlier.RefreshToken, sdClientID, sdSecret)
	sdExpectInvalidGrant(t, "earlier refresh token", status, body)
}

func TestSubjectDeprovisioning_NormalRedemptionUnchanged(t *testing.T) {
	t.Parallel()
	env := newSDCodeEnv(t)
	tok := env.issue(t)
	status, body := sdRefresh(t, env.tk, tok.RefreshToken, sdClientID, sdSecret)
	if status != http.StatusOK || body["access_token"] == nil {
		t.Fatalf("refresh status=%d body=%v, want 200", status, body)
	}
	if n := len(env.capture.EventsByName(string(op.AuditTokenRevoked))); n != 0 {
		t.Fatalf("%d %s events on a normal redemption", n, op.AuditTokenRevoked)
	}
}

// TestScenario_DEV_026_TokenRequestAccountNotFound pins that an approved
// device_code whose subject left the user store earns invalid_grant, and
// that the subject's earlier device-issued tokens stop working.
//
// Spec: RFC 6749 §5.2.
func TestScenario_DEV_026_TokenRequestAccountNotFound(t *testing.T) {
	t.Parallel()
	users, withUsers := newSDUsers(devDefaultSubject)
	p := newDevProviderWithResources(t, []string{"openid", "offline_access"}, nil,
		testkit.WithOptions(withUsers, op.WithFeature(feature.Introspect)))
	var dc string
	redeem := func(t *testing.T) (int, map[string]any) {
		t.Helper()
		dc = p.issueDeviceCode(t, "openid offline_access")
		p.approveDeviceCodeAt(t, dc, devDefaultSubject, time.Now().UTC())
		return p.tokenForm(t, url.Values{"grant_type": {devURNDeviceCode}, "device_code": {dc}})
	}
	status, earlier := redeem(t)
	if status != http.StatusOK {
		t.Fatalf("device_code status=%d body=%v", status, earlier)
	}
	at, _ := earlier["access_token"].(string)
	rt, _ := earlier["refresh_token"].(string)
	if at == "" || rt == "" {
		t.Fatalf("device_code response lacks access or refresh token: %v", earlier)
	}

	users.gone.Store(true)
	status, body := redeem(t)
	sdExpectInvalidGrant(t, "device_code", status, body)
	status, body = sdRefresh(t, p.tk, rt, p.client.ID, devClientSecret)
	sdExpectInvalidGrant(t, "device-issued refresh token", status, body)
	sdExpectInactive(t, p.tk, at, p.client.ID, devClientSecret)

	// The refused approval was spent: it does not redeem once the
	// subject is back.
	users.gone.Store(false)
	status, body = p.tokenForm(t, url.Values{"grant_type": {devURNDeviceCode}, "device_code": {dc}})
	if status != http.StatusBadRequest {
		t.Fatalf("refused device_code re-polled: status=%d body=%v", status, body)
	}
	expectError(t, body, "expired_token")
}

func TestSubjectDeprovisioning_CIBARefusedAndEarlierTokensDead(t *testing.T) {
	t.Parallel()
	users, withUsers := newSDUsers(cibaDefaultSubject)
	p := newCIBAProvider(t, []string{"openid", "offline_access"}, withUsers, op.WithFeature(feature.Introspect))
	redeem := func(t *testing.T) (int, map[string]any) {
		t.Helper()
		status, body, _ := p.bcAuthorizeForm(t, url.Values{
			"login_hint": {cibaKnownLoginHint},
			"scope":      {"openid offline_access"},
		})
		if status != http.StatusOK {
			t.Fatalf("/bc-authorize status=%d body=%v", status, body)
		}
		id, _ := body["auth_req_id"].(string)
		if err := p.tk.Store.CIBARequests().Approve(context.Background(), id, cibaDefaultSubject, "", time.Now().UTC()); err != nil {
			t.Fatalf("CIBARequests.Approve: %v", err)
		}
		return sdTokenPost(t, p.tk, url.Values{"grant_type": {cibaURNGrant}, "auth_req_id": {id}}, p.client.ID, cibaClientSecret)
	}
	status, earlier := redeem(t)
	if status != http.StatusOK {
		t.Fatalf("ciba status=%d body=%v", status, earlier)
	}
	at, _ := earlier["access_token"].(string)
	rt, _ := earlier["refresh_token"].(string)
	if at == "" || rt == "" {
		t.Fatalf("ciba response lacks access or refresh token: %v", earlier)
	}

	users.gone.Store(true)
	status, body := redeem(t)
	sdExpectInvalidGrant(t, "ciba", status, body)
	status, body = sdRefresh(t, p.tk, rt, p.client.ID, cibaClientSecret)
	sdExpectInvalidGrant(t, "ciba-issued refresh token", status, body)
	sdExpectInactive(t, p.tk, at, p.client.ID, cibaClientSecret)
}
