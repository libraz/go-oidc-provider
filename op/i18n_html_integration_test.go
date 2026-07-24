package op_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

func TestDefaultHTMLDriver_WithLocaleMessagesReachAuthorizeWire(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		locale    op.Locale
		uiLocales string
		messages  map[string]string
		want      []string
	}{
		{
			name:      "registered French locale",
			locale:    "fr",
			uiLocales: "fr",
			messages: map[string]string{ //nolint:gosec // G101: UI translation keys and labels, not authentication credentials.
				"login.title":            "Connexion <Acme>",
				"login.identifier.label": "Identifiant & compte",
				"login.password.label":   "Passphrase & personnalisée",
				"login.button.submit":    "Entrer & continuer",
			},
			want: []string{
				`<html lang="fr">`,
				`<title>Connexion &lt;Acme&gt;</title>`,
				`<label>Identifiant &amp; compte<br>`,
				`<label>Passphrase &amp; personnalisée<br>`,
				`<button type="submit">Entrer &amp; continuer</button>`,
			},
		},
		{
			name:   "English overlay",
			locale: op.LocaleEnglish,
			messages: map[string]string{ //nolint:gosec // G101: UI translation keys and labels, not authentication credentials.
				"login.title":            "Sign in to <Acme>",
				"login.identifier.label": "Account & email",
				"login.password.label":   "Passphrase & custom",
				"login.button.submit":    "Enter & continue",
			},
			want: []string{
				`<html lang="en">`,
				`<title>Sign in to &lt;Acme&gt;</title>`,
				`<label>Account &amp; email<br>`,
				`<label>Passphrase &amp; custom<br>`,
				`<button type="submit">Enter &amp; continue</button>`,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			body := localizedPasswordPromptFromWire(t, tc.locale, tc.uiLocales, tc.messages)
			for _, fragment := range tc.want {
				if !strings.Contains(body, fragment) {
					t.Errorf("localized HTML missing %q; got:\n%s", fragment, body)
				}
			}
		})
	}
}

func localizedPasswordPromptFromWire(
	t *testing.T,
	locale op.Locale,
	uiLocales string,
	messages map[string]string,
) string {
	t.Helper()

	bundle, err := op.LocaleBundleFromMap(locale, messages)
	if err != nil {
		t.Fatalf("LocaleBundleFromMap(%q): %v", locale, err)
	}
	st := inmem.New()
	provider, err := op.New(
		op.WithIssuer(validIssuer),
		op.WithStore(st),
		op.WithKeyset(validKeyset(t)),
		op.WithCookieKeys(newRandomCookieKey(t)),
		op.WithLoginFlow(op.LoginFlow{
			Primary: op.PrimaryPassword{Store: st.UserPasswords()},
		}),
		op.WithLocale(bundle),
		op.WithStaticClients(op.PublicClient{
			ID:           "localized-html-client",
			RedirectURIs: []string{"https://rp.example.com/cb"},
			Scopes:       []string{"openid"},
		}),
	)
	if err != nil {
		t.Fatalf("op.New: %v", err)
	}

	verifier := strings.Repeat("v", 43)
	sum := sha256.Sum256([]byte(verifier))
	values := url.Values{
		"client_id":             {"localized-html-client"},
		"response_type":         {"code"},
		"redirect_uri":          {"https://rp.example.com/cb"},
		"scope":                 {"openid"},
		"state":                 {"state-i18n-html"},
		"nonce":                 {"nonce-i18n-html"},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	if uiLocales != "" {
		values.Set("ui_locales", uiLocales)
	}
	authReq := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		validIssuer+"/oidc/auth?"+values.Encode(),
		http.NoBody,
	)
	authRec := httptest.NewRecorder()
	provider.ServeHTTP(authRec, authReq)
	authResp := authRec.Result()
	defer authResp.Body.Close()
	if authResp.StatusCode != http.StatusFound {
		raw, _ := io.ReadAll(authResp.Body)
		t.Fatalf("authorize status = %d, want 302; body=%s", authResp.StatusCode, raw)
	}
	location, err := authResp.Location()
	if err != nil {
		t.Fatalf("authorize Location: %v", err)
	}
	if !strings.HasPrefix(location.Path, "/oidc/interaction/") {
		t.Fatalf("authorize Location = %s, want interaction path", location)
	}

	stepReq := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		validIssuer+location.RequestURI(),
		http.NoBody,
	)
	for _, c := range authResp.Cookies() {
		stepReq.AddCookie(c)
	}
	stepRec := httptest.NewRecorder()
	provider.ServeHTTP(stepRec, stepReq)
	stepResp := stepRec.Result()
	defer stepResp.Body.Close()
	raw, err := io.ReadAll(stepResp.Body)
	if err != nil {
		t.Fatalf("read interaction response: %v", err)
	}
	if stepResp.StatusCode != http.StatusOK {
		t.Fatalf("interaction status = %d, want 200; body=%s", stepResp.StatusCode, raw)
	}
	if got := stepResp.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Fatalf("interaction Content-Type = %q, want text/html", got)
	}
	return string(raw)
}
