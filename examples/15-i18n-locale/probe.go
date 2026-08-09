//go:build example

// probe.go — self-verify probe for example 15-i18n-locale.
//
// The probe stands up an in-process httptest server, drives
// /authorize → /interaction GET against each row of the locale
// priority chain (PreferredLocaleStore → ui_locales → __Host-oidc_locale
// cookie → Accept-Language → default), and asserts the resolved
// [interaction.Prompt] locale matches the expectation. The probe
// prints PASS / FAIL per row so the example output makes the
// resolver behaviour visible without a browser session, and fails
// the process before the public listener starts if any row regresses.

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

	"github.com/libraz/go-oidc-provider/op"
)

// selfVerifyLocaleChain stands up an in-process httptest server,
// drives /authorize → /interaction GET against each row of the locale
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
		return fmt.Errorf("%d row(s) of the locale priority chain mismatched the expected locale", failed)
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
	authReq, err := localeRequest(baseURL+"/oidc/auth?"+values.Encode(), cookieValue, acceptLanguage)
	if err != nil {
		return "", err
	}
	authResp, err := client.Do(authReq)
	if err != nil {
		return "", err
	}
	defer func() { _ = authResp.Body.Close() }()
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

	stepReq, err := localeRequest(baseURL+location.Path, cookieValue, acceptLanguage)
	if err != nil {
		return "", err
	}
	stepResp, err := client.Do(stepReq)
	if err != nil {
		return "", err
	}
	defer func() { _ = stepResp.Body.Close() }()
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

// localeRequest builds a GET request for rawURL carrying the two
// transport-level links of the chain: the Accept-Language header and
// the __Host-oidc_locale cookie. Either is omitted when empty, so a
// row can exercise one link in isolation. Both the /authorize and the
// /interaction leg of a probe send the same pair — the resolver must
// reach the same locale at either endpoint.
func localeRequest(rawURL, cookieValue, acceptLanguage string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, rawURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	if acceptLanguage != "" {
		req.Header.Set("Accept-Language", acceptLanguage)
	}
	if cookieValue != "" {
		req.AddCookie(&http.Cookie{Name: "__Host-oidc_locale", Value: cookieValue})
	}
	return req, nil
}

// pkceChallenge derives the SHA-256 base64url challenge from verifier.
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
