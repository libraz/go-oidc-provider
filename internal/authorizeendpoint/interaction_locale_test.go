package authorizeendpoint_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// TestInteractionLocale_PriorityChain pins the locale priority chain for
// the interaction prompt envelope: the layer the embedder supplies
// MUST win against the layers below it. A single test exercises all
// four layers below the optional PreferredLocaleStore (which lives in
// op_test.go because it requires a public Option) so a regression in
// the resolver wiring fails one row at a time.
//
// The flow drives /authorize → /interaction GET and asserts the
// prompt envelope's `locale` field. The priority order is
// ui_locales → cookie → Accept-Language → default.
func TestInteractionLocale_PriorityChain(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name           string
		uiLocales      string
		cookie         string
		acceptLanguage string
		want           string
	}{
		{
			name:           "ui_locales wins over cookie / accept-language",
			uiLocales:      "ja",
			cookie:         "en",
			acceptLanguage: "en",
			want:           "ja",
		},
		{
			name:           "cookie wins over accept-language",
			cookie:         "ja",
			acceptLanguage: "en",
			want:           "ja",
		},
		{
			name:           "accept-language wins over default when no other signal",
			acceptLanguage: "ja-JP",
			want:           "ja",
		},
		{
			name: "default falls back to en when no signal matches",
			want: "en",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			locale := fetchPromptLocale(t, tc.uiLocales, tc.cookie, tc.acceptLanguage)
			if locale != tc.want {
				t.Errorf("prompt.locale = %q, want %q", locale, tc.want)
			}
		})
	}
}

// TestInteractionLocale_AvailableAndHint pins the rest of the prompt's
// i18n envelope: `ui_locales_hint` echoes the RP's request parameter and
// `locales_available` lists every registered tag. Embedder SPAs use
// the latter to build a language picker without re-fetching
// discovery.
func TestInteractionLocale_AvailableAndHint(t *testing.T) {
	t.Parallel()

	env := fetchPromptEnvelope(t, "ja en", "", "")
	if got, _ := env["locale"].(string); got != "ja" {
		t.Errorf("prompt.locale = %v, want ja", env["locale"])
	}
	hint, _ := env["ui_locales_hint"].([]any)
	if len(hint) != 2 || hint[0] != "ja" || hint[1] != "en" {
		t.Errorf("ui_locales_hint = %v, want [ja en]", hint)
	}
	avail, _ := env["locales_available"].([]any)
	// Seed bundles ship en + ja; the test does not register additional
	// locales so the slice has exactly two entries.
	if len(avail) != 2 {
		t.Fatalf("locales_available = %v, want length 2", avail)
	}
	gotEN, gotJA := false, false
	for _, v := range avail {
		switch v {
		case "en":
			gotEN = true
		case "ja":
			gotJA = true
		}
	}
	if !gotEN || !gotJA {
		t.Errorf("locales_available = %v, want en + ja", avail)
	}
}

// fetchPromptLocale runs an authorize → interaction GET round-trip and
// returns the prompt envelope's `locale` field. The helper exists so
// each priority-chain row reads as one line.
func fetchPromptLocale(t *testing.T, uiLocales, cookie, acceptLanguage string) string {
	t.Helper()
	env := fetchPromptEnvelope(t, uiLocales, cookie, acceptLanguage)
	got, _ := env["locale"].(string)
	return got
}

// fetchPromptEnvelope drives /authorize then GET /interaction/{uid}
// and returns the decoded prompt JSON. The test client carries an
// optional __Host-oidc_locale cookie + Accept-Language header so each
// row of the priority chain can be exercised in isolation.
func fetchPromptEnvelope(t *testing.T, uiLocales, cookie, acceptLanguage string) map[string]any {
	t.Helper()

	clock := fakeClock{now: time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)}
	tk := testkit.NewProvider(t, testkit.WithClock(clock))
	const secret = "rp-secret"
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      "rp-locale",
		SecretHash:              hash,
		RedirectURIs:            []string{"https://rp.testkit.invalid/callback"},
		Scopes:                  []string{"openid", "profile"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	client := tk.HTTPClient(jar)

	values := e2eAuthorizeValues(rp.ID, rp.RedirectURIs[0])
	values.Set("scope", "openid profile")
	if uiLocales != "" {
		values.Set("ui_locales", uiLocales)
	}
	authorizeURL := tk.Server.URL + "/oidc/auth?" + values.Encode()

	authReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, authorizeURL, http.NoBody)
	if err != nil {
		t.Fatalf("authorize request: %v", err)
	}
	if acceptLanguage != "" {
		authReq.Header.Set("Accept-Language", acceptLanguage)
	}
	if cookie != "" {
		authReq.AddCookie(&http.Cookie{Name: "__Host-oidc_locale", Value: cookie})
	}
	authResp, err := client.Do(authReq)
	if err != nil {
		t.Fatalf("authorize Do: %v", err)
	}
	defer authResp.Body.Close()
	if authResp.StatusCode != http.StatusFound {
		dump, _ := io.ReadAll(authResp.Body)
		t.Fatalf("authorize status=%d body=%s", authResp.StatusCode, string(dump))
	}
	location, err := authResp.Location()
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	if !strings.HasPrefix(location.Path, "/oidc/interaction/") {
		t.Fatalf("authorize redirected outside /oidc/interaction/: %s", location.String())
	}

	stepReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, tk.Server.URL+location.Path, http.NoBody)
	if err != nil {
		t.Fatalf("interaction request: %v", err)
	}
	if acceptLanguage != "" {
		stepReq.Header.Set("Accept-Language", acceptLanguage)
	}
	if cookie != "" {
		stepReq.AddCookie(&http.Cookie{Name: "__Host-oidc_locale", Value: cookie})
	}
	stepResp, err := client.Do(stepReq)
	if err != nil {
		t.Fatalf("interaction Do: %v", err)
	}
	defer stepResp.Body.Close()
	if stepResp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(stepResp.Body)
		t.Fatalf("interaction status=%d body=%s", stepResp.StatusCode, string(dump))
	}
	var env map[string]any
	if err := json.NewDecoder(stepResp.Body).Decode(&env); err != nil {
		t.Fatalf("decode prompt: %v", err)
	}
	return env
}
