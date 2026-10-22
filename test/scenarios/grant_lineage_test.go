package scenarios_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
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

// Every credential the OP issues for an end user descends from a grant
// record: revoking that grant or its subject, or deleting the subject
// from the user store, reaches the credential whichever grant type
// minted it.

const (
	glCodeClient   = "rp-lineage"
	glCallerClient = "rp-lineage-caller"
	glSecret       = "rp-lineage-secret" //nolint:gosec // test fixture: not a real credential.
	glCallback     = "https://rp.lineage.example.test/callback"
)

var errGLUserStoreDown = errors.New("user store unreachable")

// glUsers is a user store the test can empty or break after tokens
// were issued.
type glUsers struct {
	store.UserStore
	gone  atomic.Bool
	fault atomic.Bool
}

func (u *glUsers) FindBySubject(ctx context.Context, sub string) (*store.User, error) {
	switch {
	case u.fault.Load():
		return nil, errGLUserStoreDown
	case u.gone.Load():
		return nil, store.ErrNotFound
	}
	return u.UserStore.FindBySubject(ctx, sub)
}

type glEnv struct {
	tk    *testkit.Provider
	users *glUsers
}

// newGLEnv builds a provider with an authorization_code client whose
// tokens serve as subject_tokens, and a second client allowed to
// exchange them for an access token plus a refresh token.
func newGLEnv(t *testing.T, extra ...op.Option) *glEnv {
	t.Helper()
	backing := inmem.New()
	backing.PutUser(context.Background(), &store.User{Subject: scenariokit.DefaultSubject})
	users := &glUsers{UserStore: backing.Users()}
	opts := append([]op.Option{
		op.WithUserStore(users),
		op.WithFeature(feature.Introspect),
		op.RegisterTokenExchange(txDecisionPolicy{decision: &op.TokenExchangeDecision{IssueRefreshToken: op.PtrBool(true)}}),
	}, extra...)
	tk := testkit.NewProvider(t, testkit.WithOptions(opts...))
	hash, err := op.HashClientSecret(glSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      glCodeClient,
		SecretHash:              hash,
		RedirectURIs:            []string{glCallback},
		Scopes:                  []string{"openid", "offline_access", "read"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      glCallerClient,
		SecretHash:              hash,
		GrantTypes:              []string{txGrantType, "refresh_token"},
		Scopes:                  []string{"openid", "offline_access", "read"},
		Resources:               []string{txTargetAud},
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	return &glEnv{tk: tk, users: users}
}

// subjectToken runs a code flow for the default subject and returns its
// access token.
func (e *glEnv) subjectToken(t *testing.T) string {
	t.Helper()
	pkce := scenariokit.NewPKCEPair("")
	flow := scenariokit.RunCodeFlow(t, e.tk, scenariokit.DefaultSubject, scenariokit.AuthorizeParams{
		ClientID: glCodeClient, RedirectURI: glCallback, Scope: "openid read", PKCE: pkce,
	})
	tok := scenariokit.ExchangeCode(t, e.tk, scenariokit.ExchangeCodeRequest{
		Code: flow.Code, RedirectURI: glCallback, Verifier: pkce.Verifier,
		ClientID: glCodeClient, ClientSecret: glSecret,
	})
	if tok.StatusCode != http.StatusOK || tok.AccessToken == "" {
		t.Fatalf("/token status=%d body=%v", tok.StatusCode, tok.Raw)
	}
	return tok.AccessToken
}

func (e *glEnv) exchange(t *testing.T, subjectToken string) (int, map[string]any) {
	t.Helper()
	return sdTokenPost(t, e.tk, url.Values{
		"grant_type":         {txGrantType},
		"subject_token":      {subjectToken},
		"subject_token_type": {txTokenTypeAT},
		"resource":           {txTargetAud},
	}, glCallerClient, glSecret)
}

func (e *glEnv) issueExchanged(t *testing.T) (accessToken, refreshToken string) {
	t.Helper()
	status, body := e.exchange(t, e.subjectToken(t))
	accessToken, _ = body["access_token"].(string)
	refreshToken, _ = body["refresh_token"].(string)
	if status != http.StatusOK || accessToken == "" || refreshToken == "" {
		t.Fatalf("exchange status=%d body=%v, want access and refresh tokens", status, body)
	}
	return accessToken, refreshToken
}

// TestGrantLineage_TokenExchangeRefusedForDeprovisionedSubject pins that
// token exchange looks the subject_token's subject up like every other
// redemption, and that a chain it rooted stops rotating once the subject
// is gone.
func TestGrantLineage_TokenExchangeRefusedForDeprovisionedSubject(t *testing.T) {
	t.Parallel()
	env := newGLEnv(t)
	subjectToken := env.subjectToken(t)
	status, body := env.exchange(t, subjectToken)
	rt, _ := body["refresh_token"].(string)
	if status != http.StatusOK || rt == "" {
		t.Fatalf("exchange status=%d body=%v, want a refresh token", status, body)
	}

	env.users.fault.Store(true)
	status, body = env.exchange(t, subjectToken)
	if status != http.StatusInternalServerError || body["error"] != "server_error" {
		t.Fatalf("exchange on a user-store fault: status=%d body=%v, want 500 server_error", status, body)
	}
	env.users.fault.Store(false)

	env.users.gone.Store(true)
	status, body = sdRefresh(t, env.tk, rt, glCallerClient, glSecret)
	sdExpectInvalidGrant(t, "exchange-rooted refresh", status, body)
	status, body = env.exchange(t, subjectToken)
	sdExpectInvalidGrant(t, "token exchange", status, body)
}

// TestGrantLineage_RevokeSubjectReachesEveryGrantType pins that
// RevokeSubject retires what device_code, CIBA and token exchange issued,
// not only what authorization_code did.
func TestGrantLineage_RevokeSubjectReachesEveryGrantType(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	t.Run("token exchange", func(t *testing.T) {
		t.Parallel()
		env := newGLEnv(t)
		at, rt := env.issueExchanged(t)
		if err := env.tk.OP.RevokeSubject(ctx, scenariokit.DefaultSubject); err != nil {
			t.Fatalf("RevokeSubject: %v", err)
		}
		sdExpectInactive(t, env.tk, at, glCallerClient, glSecret)
		status, body := sdRefresh(t, env.tk, rt, glCallerClient, glSecret)
		sdExpectInvalidGrant(t, "exchange-rooted refresh after RevokeSubject", status, body)
	})

	t.Run("device_code", func(t *testing.T) {
		t.Parallel()
		p := newDevProviderWithResources(t, []string{"openid", "offline_access"}, nil,
			testkit.WithOptions(op.WithFeature(feature.Introspect)))
		dc := p.issueDeviceCode(t, "openid offline_access")
		p.approveDeviceCode(t, dc, devDefaultSubject)
		status, body := p.tokenForm(t, url.Values{"grant_type": {devURNDeviceCode}, "device_code": {dc}})
		if status != http.StatusOK {
			t.Fatalf("device_code status=%d body=%v", status, body)
		}
		if err := p.tk.OP.RevokeSubject(ctx, devDefaultSubject); err != nil {
			t.Fatalf("RevokeSubject: %v", err)
		}
		sdExpectInactive(t, p.tk, body["access_token"].(string), p.client.ID, devClientSecret)
		status, body = sdRefresh(t, p.tk, body["refresh_token"].(string), p.client.ID, devClientSecret)
		sdExpectInvalidGrant(t, "device-issued refresh after RevokeSubject", status, body)
	})

	t.Run("ciba", func(t *testing.T) {
		t.Parallel()
		p := newCIBAProvider(t, []string{"openid", "offline_access"}, op.WithFeature(feature.Introspect))
		scenariokit.SeedSubject(t, p.tk, cibaDefaultSubject)
		status, bc, _ := p.bcAuthorizeForm(t, url.Values{
			"login_hint": {cibaKnownLoginHint},
			"scope":      {"openid offline_access"},
		})
		if status != http.StatusOK {
			t.Fatalf("/bc-authorize status=%d body=%v", status, bc)
		}
		id, _ := bc["auth_req_id"].(string)
		if err := p.tk.Store.CIBARequests().Approve(ctx, id, cibaDefaultSubject, "", time.Now().UTC()); err != nil {
			t.Fatalf("CIBARequests.Approve: %v", err)
		}
		status, body := sdTokenPost(t, p.tk, url.Values{"grant_type": {cibaURNGrant}, "auth_req_id": {id}}, p.client.ID, cibaClientSecret)
		if status != http.StatusOK {
			t.Fatalf("ciba status=%d body=%v", status, body)
		}
		if err := p.tk.OP.RevokeSubject(ctx, cibaDefaultSubject); err != nil {
			t.Fatalf("RevokeSubject: %v", err)
		}
		sdExpectInactive(t, p.tk, body["access_token"].(string), p.client.ID, cibaClientSecret)
		status, body = sdRefresh(t, p.tk, body["refresh_token"].(string), p.client.ID, cibaClientSecret)
		sdExpectInvalidGrant(t, "ciba-issued refresh after RevokeSubject", status, body)
	})
}

// TestGrantLineage_RefreshGrantIDResolvesForTheClient pins that a
// rotation advertises grant_id only when that identifier is a grant the
// client can address: a device chain's own grant, never the subject_token
// grant a token-exchange chain descends from.
func TestGrantLineage_RefreshGrantIDResolvesForTheClient(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	gm := op.WithGrantManagement([]op.GrantManagementAction{op.GrantActionQuery, op.GrantActionRevoke}, false)

	p := newDevProviderWithResources(t, []string{"openid", "offline_access"}, nil, testkit.WithOptions(gm))
	dc := p.issueDeviceCode(t, "openid offline_access")
	p.approveDeviceCode(t, dc, devDefaultSubject)
	status, body := p.tokenForm(t, url.Values{"grant_type": {devURNDeviceCode}, "device_code": {dc}})
	if status != http.StatusOK {
		t.Fatalf("device_code status=%d body=%v", status, body)
	}
	status, body = sdRefresh(t, p.tk, body["refresh_token"].(string), p.client.ID, devClientSecret)
	if status != http.StatusOK {
		t.Fatalf("device refresh status=%d body=%v", status, body)
	}
	grantID, _ := body["grant_id"].(string)
	g, err := p.tk.Store.Grants().Find(ctx, grantID)
	if err != nil || g.ClientID != p.client.ID {
		t.Errorf("device refresh grant_id=%q resolves to (%+v, %v), want a grant of %s", grantID, g, err, p.client.ID)
	}

	env := newGLEnv(t, gm)
	_, rt := env.issueExchanged(t)
	status, body = sdRefresh(t, env.tk, rt, glCallerClient, glSecret)
	if status != http.StatusOK {
		t.Fatalf("exchange refresh status=%d body=%v", status, body)
	}
	if got, ok := body["grant_id"]; ok {
		t.Errorf("exchange-rooted refresh advertised grant_id=%v; the grant belongs to %s", got, glCodeClient)
	}
}

// TestGrantLineage_NoGrantImpliesConsentTheUserDidNotGive pins that a
// redemption writes a Grant — the record /authorize reads as consent —
// only for the client the user approved: device_code writes one for the
// device client, while token exchange and a custom grant write none for
// the client that ran them.
func TestGrantLineage_NoGrantImpliesConsentTheUserDidNotGive(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	env := newGLEnv(t)
	env.issueExchanged(t)
	if _, err := env.tk.Store.Grants().FindBySubjectClient(ctx, scenariokit.DefaultSubject, glCallerClient); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("token exchange left a grant for %s: err=%v", glCallerClient, err)
	}
	if list, err := env.tk.Store.Grants().ListBySubject(ctx, scenariokit.DefaultSubject); err != nil || len(list) != 1 || list[0].ClientID != glCodeClient {
		t.Errorf("subject grants after exchange = (%d, %v), want only the %s consent", len(list), err, glCodeClient)
	}

	tk, client := newOpaqueSubjectProvider(t)
	osCustomGrantChain(t, tk)
	if _, err := tk.Store.Grants().FindBySubjectClient(ctx, osWireSubject, client.ID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("custom grant left a grant for %s: err=%v", client.ID, err)
	}

	p := newDevProvider(t, []string{"openid"})
	dc := p.issueDeviceCode(t, "openid")
	p.approveDeviceCode(t, dc, devDefaultSubject)
	if status, body := p.tokenForm(t, url.Values{"grant_type": {devURNDeviceCode}, "device_code": {dc}}); status != http.StatusOK {
		t.Fatalf("device_code status=%d body=%v", status, body)
	}
	if g, err := p.tk.Store.Grants().FindBySubjectClient(ctx, devDefaultSubject, p.client.ID); err != nil || g.ClientID != p.client.ID {
		t.Errorf("device_code grant = (%+v, %v), want the approved client's consent", g, err)
	}
}
