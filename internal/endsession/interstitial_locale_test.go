package endsession_test

import (
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/endsession"
	"github.com/libraz/go-oidc-provider/internal/i18n"
)

var hiddenFieldRE = regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)">`)

// TestInterstitial_UILocalesSurvivesConfirmation pins that the confirmation
// form carries ui_locales, so the logged-out page the POST renders resolves
// the same language as the confirmation page the GET rendered.
func TestInterstitial_UILocalesSurvivesConfirmation(t *testing.T) {
	t.Parallel()

	bundles, err := i18n.DefaultBundles()
	if err != nil {
		t.Fatalf("DefaultBundles: %v", err)
	}
	resolver, err := i18n.NewResolver(i18n.English, bundles...)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}
	h := newHarness(t)
	deps := h.deps
	deps.LocaleResolver = resolver
	mux := http.NewServeMux()
	mux.Handle(h.endSessionPath, endsession.Handler(deps))
	h.deps, h.handler = deps, mux

	cookieValue, _ := h.issueSession(t)
	getResp := h.doGET(t, url.Values{"ui_locales": {"ja"}}, cookieValue)
	body := readBody(t, getResp)
	if getResp.StatusCode != http.StatusOK || !strings.Contains(body, `<html lang="ja">`) {
		t.Fatalf("GET status=%d, want a Japanese confirmation page; body=%s", getResp.StatusCode, body)
	}
	tok := readConfirmCookie(getResp)
	if tok == "" {
		t.Fatal("interstitial GET did not set the confirmation cookie")
	}

	form := url.Values{}
	for _, m := range hiddenFieldRE.FindAllStringSubmatch(body, -1) {
		if m[2] != "" {
			form.Set(m[1], html.UnescapeString(m[2]))
		}
	}
	postResp := confirmPOST(t, h, form, cookieValue, tok)
	postBody := readBody(t, postResp)
	if postResp.StatusCode != http.StatusOK || !strings.Contains(postBody, `<html lang="ja">`) {
		t.Fatalf("POST status=%d, want a Japanese logged-out page; body=%s", postResp.StatusCode, postBody)
	}
}
