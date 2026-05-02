//go:build example

// Example 16 demonstrates locale negotiation for the OP's interaction
// prompt envelope. The OP picks the rendered language from a five-
// layer priority chain — PreferredLocaleStore → ui_locales request
// parameter → __Host-oidc_locale cookie → Accept-Language header →
// default locale — and stamps the result onto every prompt as
// `locale`, alongside `ui_locales_hint` (RP raw list) and
// `locales_available` (registered tags). SPAs read the envelope on
// /oidc/interaction/{uid} and set <html lang> / pick bundles.
//
// Run with the example build tag:
//
//	go run -tags example ./examples/16-i18n-locale
//
// Startup runs an in-process self-verify probe that drives every row
// of the priority chain through an httptest server and prints a
// PASS / FAIL summary. The listener then comes up on :8080 so
// embedders can curl the discovery and authorize endpoints manually:
//
//	curl -s 'http://localhost:8080/.well-known/openid-configuration' \
//	  | jq .ui_locales_supported
//	# returns ["en","ja","fr"] — seed en + ja + the registered fr.
//
//	# Drive ui_locales=ja and read the resolved locale from the
//	# interaction prompt envelope:
//	curl -sL --cookie-jar j.txt --cookie j.txt \
//	  'http://localhost:8080/oidc/auth?client_id=demo-rp&response_type=code&redirect_uri=http://127.0.0.1:5173/callback&scope=openid&state=s&nonce=n&code_challenge=...&code_challenge_method=S256&ui_locales=ja' \
//	  | jq -r '.locale'
//
// The OP ships seed bundles for English (en) and Japanese (ja); this
// example registers a French bundle on top and switches the default
// to French. To override an existing message, register a bundle for
// the same locale — the later registration wins per key.
//
// PRODUCTION CAVEATS:
//   - Keys: ephemeral; load from a vault / KMS in production.
//   - Store: in-memory; use op/storeadapter/sql or composite.
//   - Listener: plain HTTP; front behind TLS-terminating ingress.
//   - Self-verify probe: useful for the example, NOT for production.
//     Real deployments verify locale resolution through their CI
//     scenario suite (test/scenarios/i18n_test.go).
//   - Locale bundles: load from a versioned message catalogue
//     (JSON / TOML / Fluent) at startup so translators can ship
//     without recompiling the OP binary.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"

	"github.com/libraz/go-oidc-provider/examples/internal/devkeys"
	"github.com/libraz/go-oidc-provider/examples/internal/serve"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// frenchMessages is a minimal French bundle covering the consent and
// login surfaces. The seed catalogue does not ship a French entry, so
// keys this map omits fall back to the configured default locale's
// bundle (here "fr" itself, then "en" through the resolver chain).
// For overrides on a seeded locale (en / ja) the bundle merges on top
// of the seed at key granularity — embedders only supply the keys
// they want to change.
var frenchMessages = map[string]string{
	"consent.title":          "Autoriser {client_name}",
	"consent.subtitle":       "{client_name} souhaite accéder à :",
	"consent.button.allow":   "Autoriser",
	"consent.button.deny":    "Annuler",
	"login.title":            "Connexion",
	"login.identifier.label": "E-mail ou nom d'utilisateur",
	"login.password.label":   "Mot de passe",
	"login.button.submit":    "Se connecter",
}

const (
	demoClientID    = "demo-rp"
	demoRedirectURI = "http://127.0.0.1:5173/callback"
	// pkceVerifier is the canonical PKCE verifier used by the
	// self-verify probe. The challenge is the SHA-256 base64url
	// digest of this string.
	pkceVerifier = "i18n-example-verifier-i18n-example-verifier-i18n-example"
)

func main() {
	keys := devkeys.MustEphemeral("i18n-1")

	french, err := op.LocaleBundleFromMap("fr", frenchMessages)
	if err != nil {
		log.Fatalf("LocaleBundleFromMap(fr): %v", err)
	}

	st := inmem.New()
	if err := seedDemoUser(st); err != nil {
		log.Fatalf("seed demo user: %v", err)
	}

	provider, err := op.New(
		op.WithIssuer("http://127.0.0.1:8080"),
		op.WithStore(st),
		op.WithKeyset(keys.Keyset()),
		op.WithCookieKeys(keys.CookieKey),
		op.WithLoginFlow(op.LoginFlow{
			Primary: op.PrimaryPassword{Store: st.UserPasswords()},
		}),
		// JSONDriver is selected so the self-verify probe and any
		// SPA fetch see a JSON envelope. Embedders that ship a
		// server-rendered UI replace this with their own
		// [interaction.Driver]; the locale field rides on the
		// [interaction.Prompt] regardless of driver shape.
		op.WithInteractionDriver(interaction.JSONDriver{}),
		// Register the French bundle on top of the seed en / ja
		// bundles, then make French the fallback when no signal in
		// the priority chain matches a registered locale.
		op.WithLocale(french),
		op.WithDefaultLocale("fr"),
		op.WithStaticClients(
			op.PublicClient{
				ID:           demoClientID,
				RedirectURIs: []string{demoRedirectURI},
				Scopes:       []string{"openid", "profile"},
			},
		),
	)
	if err != nil {
		log.Fatalf("op.New: %v", err)
	}

	if err := selfVerifyLocaleChain(provider); err != nil {
		log.Fatalf("self-verify: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", provider)

	log.Println("registered locales: en, ja (seed) + fr (custom); default = fr")
	log.Println("self-verify probe PASSED — listening on :8080")
	log.Println("hit /.well-known/openid-configuration and read ui_locales_supported to verify discovery")
	if err := serve.Listen(":8080", mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}

// selfVerifyLocaleChain stands up an in-process httptest server,
// drives /authorize → /interaction GET against each row of the §L.2
// priority chain, and asserts the resolved locale matches the
// expectation. The probe prints a PASS / FAIL line per row so the
// example output makes the resolver behaviour visible without a
// browser session. Returns the first non-nil error if any row
// disagrees with the expected outcome.
func selfVerifyLocaleChain(provider *op.Provider) error {
	srv := httptest.NewServer(provider)
	defer srv.Close()

	cases := []struct {
		name           string
		uiLocales      string
		cookie         string
		acceptLanguage string
		want           string
	}{
		{name: "ui_locales=ja → ja", uiLocales: "ja", want: "ja"},
		{name: "ui_locales=es (unregistered) → fr (default)", uiLocales: "es", want: "fr"},
		{name: "cookie=ja, no ui_locales → ja", cookie: "ja", want: "ja"},
		{name: "Accept-Language=en-US → en (sub-tag)", acceptLanguage: "en-US,en;q=0.9", want: "en"},
		{name: "no signal → fr (default)", want: "fr"},
	}
	failed := 0
	for _, tc := range cases {
		got, err := probeInteractionLocale(srv.URL, tc.uiLocales, tc.cookie, tc.acceptLanguage)
		if err != nil {
			log.Printf("FAIL %s: probe error: %v", tc.name, err)
			failed++
			continue
		}
		if got != tc.want {
			log.Printf("FAIL %s: prompt.locale=%q want %q", tc.name, got, tc.want)
			failed++
			continue
		}
		log.Printf("PASS %s", tc.name)
	}
	if failed > 0 {
		return fmt.Errorf("%d row(s) of the §L.2 chain mismatched the expected locale", failed)
	}
	return nil
}

// probeInteractionLocale drives /authorize → /interaction GET against
// baseURL with the supplied chain inputs and returns the prompt
// envelope's resolved `locale`.
func probeInteractionLocale(baseURL, uiLocales, cookieValue, acceptLanguage string) (string, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return "", err
	}
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	values := url.Values{
		"client_id":             {demoClientID},
		"response_type":         {"code"},
		"redirect_uri":          {demoRedirectURI},
		"scope":                 {"openid"},
		"state":                 {"s"},
		"nonce":                 {"n-i18n"},
		"code_challenge":        {pkceChallenge(pkceVerifier)},
		"code_challenge_method": {"S256"},
	}
	if uiLocales != "" {
		values.Set("ui_locales", uiLocales)
	}
	authReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		baseURL+"/oidc/auth?"+values.Encode(), http.NoBody)
	if err != nil {
		return "", err
	}
	if acceptLanguage != "" {
		authReq.Header.Set("Accept-Language", acceptLanguage)
	}
	if cookieValue != "" {
		authReq.AddCookie(&http.Cookie{Name: "__Host-oidc_locale", Value: cookieValue})
	}
	authResp, err := client.Do(authReq)
	if err != nil {
		return "", err
	}
	defer authResp.Body.Close()
	if authResp.StatusCode != http.StatusFound {
		dump, _ := io.ReadAll(authResp.Body)
		return "", fmt.Errorf("authorize status=%d body=%s", authResp.StatusCode, string(dump))
	}
	location, err := authResp.Location()
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(location.Path, "/oidc/interaction/") {
		return "", errors.New("authorize redirected outside /oidc/interaction/: " + location.String())
	}

	stepReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, baseURL+location.Path, http.NoBody)
	if err != nil {
		return "", err
	}
	if acceptLanguage != "" {
		stepReq.Header.Set("Accept-Language", acceptLanguage)
	}
	if cookieValue != "" {
		stepReq.AddCookie(&http.Cookie{Name: "__Host-oidc_locale", Value: cookieValue})
	}
	stepResp, err := client.Do(stepReq)
	if err != nil {
		return "", err
	}
	defer stepResp.Body.Close()
	if stepResp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(stepResp.Body)
		return "", fmt.Errorf("interaction status=%d body=%s", stepResp.StatusCode, string(dump))
	}
	var env map[string]any
	if err := json.NewDecoder(stepResp.Body).Decode(&env); err != nil {
		return "", err
	}
	locale, _ := env["locale"].(string)
	return locale, nil
}

// pkceChallenge derives the SHA-256 base64url challenge from verifier.
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// seedDemoUser plants a single demo user so the LoginFlow can render
// its password prompt during the self-verify probe. The password is
// never submitted; the probe terminates after reading the prompt
// envelope, but an empty user store would short-circuit the flow.
func seedDemoUser(st *inmem.Store) error {
	hash, err := op.HashPassword("demo")
	if err != nil {
		return err
	}
	st.PutUserWithPassword(context.Background(), &store.User{
		Subject: "demo-user",
		Claims: map[string]any{
			"name":  "Demo User",
			"email": "demo@example.com",
		},
	}, "demo", hash)
	return nil
}
