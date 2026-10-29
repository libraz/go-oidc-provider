package op_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	authntotp "github.com/libraz/go-oidc-provider/internal/authn/totp"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/op/totpkit"
)

const (
	acrSSOCustom   = "urn:example:mfa"
	acrSSOUsername = "acr-sso-user"
	acrSSOPassword = "correct horse battery staple"
	acrSSOSubject  = "user-acr-sso"
	acrSSORedirect = "https://rp.testkit.invalid/callback"
	acrSSOAuthPath = "/oidc/auth"
)

type acrSSOClock struct{ now time.Time }

func (c acrSSOClock) Now() time.Time { return c.now }

// acrSSOFixture is a password-first Provider whose TOTP step runs for the
// custom acr, with ACRLevels mapping that acr to AAL2.
type acrSSOFixture struct {
	t          *testing.T
	srv        *httptest.Server
	cl         *http.Client
	clock      acrSSOClock
	totpSecret []byte
}

func newACRSSOFixture(t *testing.T) *acrSSOFixture {
	t.Helper()
	ctx := context.Background()
	clock := acrSSOClock{now: time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)}
	st := inmem.New(inmem.WithClock(clock))

	hash, err := op.HashPassword(acrSSOPassword)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	st.PutUserWithPassword(ctx, &store.User{Subject: acrSSOSubject}, acrSSOUsername, hash)

	totpKey := make([]byte, 32)
	if _, err := rand.Read(totpKey); err != nil {
		t.Fatalf("totp key: %v", err)
	}
	codec, err := totpkit.NewCodec(totpKey)
	if err != nil {
		t.Fatalf("totpkit.NewCodec: %v", err)
	}
	pending, err := totpkit.NewEnrolment(codec, acrSSOSubject, "acr-sso", "user@example.test")
	if err != nil {
		t.Fatalf("NewEnrolment: %v", err)
	}
	pending.Record.ConfirmedAt = clock.Now()
	if err := st.TOTPs().Put(ctx, pending.Record); err != nil {
		t.Fatalf("TOTPs.Put: %v", err)
	}
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(pending.SecretBase32)
	if err != nil {
		t.Fatalf("decode totp secret: %v", err)
	}

	rpHash, err := op.HashClientSecret("rp-acr-sso-secret")
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	if err := st.RegisterClient(ctx, &store.Client{
		ID:                      "rp-acr-sso",
		RedirectURIs:            []string{acrSSORedirect},
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"openid", "profile"},
		TokenEndpointAuthMethod: "client_secret_basic",
		SecretHash:              rpHash,
	}); err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}

	provider, err := op.New(
		op.WithIssuer(testkit.DefaultIssuer),
		op.WithStore(st),
		op.WithKeyset(op.Keyset{testkit.NewSigningKey(t, "acr-sso")}),
		op.WithCookieKeys(testkit.NewCookieKey(t)),
		op.WithInteractionDriver(testkit.AutoConsentDriver{}),
		op.WithClock(clock),
		op.WithACRPolicy(op.ACRLevels{acrSSOCustom: op.AAL2}),
		op.WithLoginFlow(op.LoginFlow{
			Primary: op.PrimaryPassword{Store: st.UserPasswords()},
			Rules: []op.Rule{
				op.RuleACR(acrSSOCustom, op.StepTOTP{Store: st.TOTPs(), EncryptionKey: totpKey}),
			},
		}),
	)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}
	srv := httptest.NewTLSServer(provider)
	t.Cleanup(srv.Close)

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	return &acrSSOFixture{
		t:   t,
		srv: srv,
		cl: &http.Client{
			Transport: srv.Client().Transport,
			Jar:       jar,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		clock:      clock,
		totpSecret: secret,
	}
}

// authorize runs GET /authorize with acrValues (none when empty) and
// returns the redirect target.
func (f *acrSSOFixture) authorize(acrValues string) *url.URL {
	f.t.Helper()
	v := url.Values{
		"client_id":             {"rp-acr-sso"},
		"response_type":         {"code"},
		"redirect_uri":          {acrSSORedirect},
		"scope":                 {"openid profile"},
		"state":                 {"state-acr-sso"},
		"nonce":                 {"nonce-acr-sso"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
	}
	if acrValues != "" {
		v.Set("acr_values", acrValues)
	}
	resp := f.do(http.MethodGet, f.srv.URL+acrSSOAuthPath+"?"+v.Encode(), "", nil)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		dump, _ := io.ReadAll(resp.Body)
		f.t.Fatalf("authorize status=%d body=%s", resp.StatusCode, dump)
	}
	loc, err := resp.Location()
	if err != nil {
		f.t.Fatalf("authorize Location: %v", err)
	}
	return loc
}

func (f *acrSSOFixture) do(method, target, csrf string, body any) *http.Response {
	f.t.Helper()
	var reader io.Reader = http.NoBody
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			f.t.Fatalf("marshal: %v", err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, target, reader)
	if err != nil {
		f.t.Fatalf("NewRequest: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", testkit.DefaultIssuer)
		req.Header.Set("X-CSRF-Token", csrf)
		req.AddCookie(&http.Cookie{Name: "__Host-oidc_csrf", Value: csrf})
	}
	resp, err := f.cl.Do(req)
	if err != nil {
		f.t.Fatalf("%s %s: %v", method, target, err)
	}
	return resp
}

// step decodes a prompt envelope and returns it with the CSRF value to
// submit against it (rotated per step, else carried over).
func (f *acrSSOFixture) step(resp *http.Response, csrf string) (map[string]any, string) {
	f.t.Helper()
	if resp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(resp.Body)
		f.t.Fatalf("prompt status=%d body=%s", resp.StatusCode, dump)
	}
	for _, c := range resp.Cookies() {
		if c.Name == "__Host-oidc_csrf" {
			csrf = c.Value
		}
	}
	env := map[string]any{}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		f.t.Fatalf("decode prompt: %v", err)
	}
	return env, csrf
}

// login walks the interaction at path through password, then TOTP when
// withTOTP is set, then consent, and returns the RP redirect.
func (f *acrSSOFixture) login(path string, withTOTP bool) *url.URL {
	f.t.Helper()
	target := f.srv.URL + path
	first := f.do(http.MethodGet, target, "", nil)
	env, csrf := f.step(first, "")
	first.Body.Close()

	resp := f.do(http.MethodPost, target, csrf, map[string]any{
		"state_ref": env["state_ref"],
		"values":    map[string]string{"username": acrSSOUsername, "password": acrSSOPassword},
	})
	if withTOTP {
		env, csrf = f.step(resp, csrf)
		resp.Body.Close()
		if got, _ := env["type"].(string); got != authntotp.PromptType {
			f.t.Fatalf("prompt after password = %q, want %q", got, authntotp.PromptType)
		}
		resp = f.do(http.MethodPost, target, csrf, map[string]any{
			"state_ref": env["state_ref"],
			"values":    map[string]string{authntotp.CodeFieldName: authntotp.Code(f.totpSecret, f.clock.Now())},
		})
	}
	if resp.StatusCode == http.StatusOK {
		env, csrf = f.step(resp, csrf)
		resp.Body.Close()
		resp = testkit.PostConsentApproval(f.t, f.cl, target, testkit.DefaultIssuer, csrf,
			stringOf(env["state_ref"]), testkit.ApprovedScopesFrom(f.t, env))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		dump, _ := io.ReadAll(resp.Body)
		f.t.Fatalf("interaction final status=%d body=%s", resp.StatusCode, dump)
	}
	loc, err := resp.Location()
	if err != nil {
		f.t.Fatalf("final Location: %v", err)
	}
	return loc
}

func stringOf(v any) string {
	s, _ := v.(string)
	return s
}

func requireRPCode(t *testing.T, loc *url.URL) {
	t.Helper()
	if !strings.HasPrefix(loc.String(), acrSSORedirect) || loc.Query().Get("code") == "" {
		t.Fatalf("redirect %s, want a code at the RP", loc)
	}
}

// TestEndToEnd_ACRSatisfiedBySession_CustomLevel pins SSO for a custom
// acr declared through ACRLevels: a session that reached the acr's level
// serves it without re-authentication, and a weaker one is sent back
// through the login.
func TestEndToEnd_ACRSatisfiedBySession_CustomLevel(t *testing.T) {
	t.Parallel()

	t.Run("AAL2 session is reused", func(t *testing.T) {
		t.Parallel()
		f := newACRSSOFixture(t)
		requireRPCode(t, f.login(f.authorize(acrSSOCustom).Path, true))

		loc := f.authorize(acrSSOCustom)
		requireRPCode(t, loc)
	})

	t.Run("AAL1 session re-authenticates", func(t *testing.T) {
		t.Parallel()
		f := newACRSSOFixture(t)
		requireRPCode(t, f.login(f.authorize("").Path, false))

		loc := f.authorize(acrSSOCustom)
		if loc.Query().Get("code") != "" || !strings.Contains(loc.Path, "/interaction/") {
			t.Fatalf("redirect %s, want the interaction for re-authentication", loc)
		}
	})
}
