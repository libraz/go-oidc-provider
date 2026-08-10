package scenarios_test

// Catalog: test/scenarios/catalog/i18n.yaml (I18N-NNN)
// Spec:
//   - OpenID Connect Core 1.0 §3.1.2.1 — ui_locales request parameter
//   - OpenID Connect Discovery 1.0 §3 — ui_locales_supported metadata
//
// Two library-level contracts have no spec clause of their own and are
// stated here in full, because the rows below pin them:
//
//   Locale resolution chain — the OP adopts the first signal that
//   matches a registered locale, walking (1) the PreferredLocaleStore
//   entry for the authenticated subject, (2) the RP's ui_locales
//   request parameter, (3) the __Host-oidc_locale cookie, (4) the
//   Accept-Language header, (5) the configured default locale ("en"
//   when unset). The same order governs SPA prompts, e-mail and SSR
//   templates, and the result is always a registered tag.
//
//   Locale switch UX — the OP reads the __Host-oidc_locale cookie at
//   chain step 3 but writes it only through
//   op.Provider.SetLocaleCookie, which the embedder calls from its own
//   endpoint. A language picker is interaction UI and belongs to the
//   Driver, so the OP never observes the choice on its own. The value
//   stored is the registered tag the input matches; an unmatched
//   locale is rejected instead of written.
//
//   SPA prompt envelope — the interaction prompt carries `locale` (the
//   resolved tag, always populated), `ui_locales_hint` (the RP's
//   ui_locales list, split but otherwise verbatim) and
//   `locales_available` (the registered locales, equal to discovery's
//   ui_locales_supported). All three are omitted when empty so an SPA
//   written against an OP without i18n keeps working.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

// i18nFakeStore satisfies [op.PreferredLocaleStore] with a fixed tag.
// The scenario tests use it to pin the head of the locale resolution
// chain without standing up a real user store.
type i18nFakeStore struct {
	tag op.Locale
}

func (s i18nFakeStore) PreferredLocale(_ context.Context, _ string) (op.Locale, error) {
	return s.tag, nil
}

// fetchI18nPrompt drives /authorize → /interaction GET against the
// supplied provider and returns the decoded prompt envelope. The
// helper attaches an optional Accept-Language header and
// __Host-oidc_locale cookie so each step of the locale resolution
// chain can be exercised in isolation. The provider is constructed by the caller
// so a row that needs WithPreferredLocaleStore can supply it.
func fetchI18nPrompt(t *testing.T, p *testkit.Provider, uiLocales, cookie, acceptLanguage string) map[string]any {
	t.Helper()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	client := p.HTTPClient(jar)

	rp := p.RegisterClient(t, testkit.ClientFixture{
		ID:           "rp-i18n",
		RedirectURIs: []string{"https://rp.testkit.invalid/callback"},
		Scopes:       []string{"openid", "profile"},
	})
	params := scenariokit.AuthorizeParams{
		ClientID:    rp.ID,
		RedirectURI: rp.RedirectURIs[0],
		Scope:       "openid profile",
		State:       scenariokit.DefaultState,
		Nonce:       "n-i18n",
		PKCE:        scenariokit.NewPKCEPair(scenariokit.DefaultPKCEVerifier),
	}
	values := params.Values()
	if uiLocales != "" {
		values.Set("ui_locales", uiLocales)
	}
	authorizeURL := p.Server.URL + "/oidc/auth?" + values.Encode()

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
	loc, err := authResp.Location()
	if err != nil {
		t.Fatalf("authorize Location: %v", err)
	}
	if !strings.HasPrefix(loc.Path, "/oidc/interaction/") {
		t.Fatalf("authorize redirected outside /oidc/interaction/: %s", loc.String())
	}

	stepReq, err := http.NewRequestWithContext(context.Background(), http.MethodGet, p.Server.URL+loc.Path, http.NoBody)
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

// TestScenario_I18N_001_PreferredLocaleStoreWinsChainHead pins chain
// step 1: when op.WithPreferredLocaleStore returns a registered
// locale for the authenticated subject, it wins against any other
// signal in the chain.
//
// The locale resolver consults the store at the head of the chain,
// but the chain walk only invokes it when [authn.State.Subject] is
// non-empty. The interaction prompt is rendered before any factor
// has bound a subject, so this row asserts the public-API contract
// rather than the wire shape: the resolver returned by
// [Provider.LocaleResolver] honours the store at the head of the
// chain. The wire-shape coverage stays with rows I18N-002 onward,
// where the chain can be exercised via /authorize round-trips.
//
// Spec: locale resolution chain (file header).
func TestScenario_I18N_001_PreferredLocaleStoreWinsChainHead(t *testing.T) {
	t.Parallel()

	store := i18nFakeStore{tag: "ja"}
	p := testkit.NewProvider(t, testkit.WithOptions(op.WithPreferredLocaleStore(store)))
	got := p.OP.LocaleResolver().Resolve(context.Background(), op.ResolveRequest{
		Subject:        "user-1",
		AcceptLanguage: "en",
	})
	if got != "ja" {
		t.Errorf("Resolve() = %q, want ja (preferred store should win over Accept-Language)", got)
	}
}

// TestScenario_I18N_002_UILocalesWinsOverCookieAndAcceptLanguage pins
// chain step 2: when the RP supplies ui_locales, the OP MUST honour
// the first registered tag in the list, ahead of any cookie or
// Accept-Language signal.
//
// Spec: OIDC Core §3.1.2.1 / locale resolution chain (file header).
func TestScenario_I18N_002_UILocalesWinsOverCookieAndAcceptLanguage(t *testing.T) {
	t.Parallel()

	p := testkit.NewProvider(t)
	env := fetchI18nPrompt(t, p, "ja", "en", "en-US")
	if got, _ := env["locale"].(string); got != "ja" {
		t.Errorf("prompt.locale = %v, want ja", env["locale"])
	}
}

// TestScenario_I18N_003_CookieWinsOverAcceptLanguage pins chain step 3:
// the __Host-oidc_locale cookie wins against Accept-Language and
// against the default locale.
//
// Spec: locale resolution chain (file header).
func TestScenario_I18N_003_CookieWinsOverAcceptLanguage(t *testing.T) {
	t.Parallel()

	p := testkit.NewProvider(t)
	env := fetchI18nPrompt(t, p, "", "ja", "en-US")
	if got, _ := env["locale"].(string); got != "ja" {
		t.Errorf("prompt.locale = %v, want ja", env["locale"])
	}
}

// TestScenario_I18N_004_AcceptLanguageHonoursLanguageSubtagFallback
// pins chain step 4: when only Accept-Language is supplied, the OP
// honours its q-value-descending order and falls back to the
// language sub-tag for unregistered full tags ("ja-JP" → "ja").
//
// Spec: locale resolution chain (file header).
func TestScenario_I18N_004_AcceptLanguageHonoursLanguageSubtagFallback(t *testing.T) {
	t.Parallel()

	p := testkit.NewProvider(t)
	env := fetchI18nPrompt(t, p, "", "", "ja-JP,en;q=0.7")
	if got, _ := env["locale"].(string); got != "ja" {
		t.Errorf("prompt.locale = %v, want ja (sub-tag fallback)", env["locale"])
	}
}

// TestScenario_I18N_005_DefaultLocaleFallback pins chain step 5: when
// no signal in the chain matches a registered locale, the OP MUST
// fall back to the configured default (or "en" when not supplied).
// The resolver guarantees the result is a registered tag.
//
// Spec: locale resolution chain (file header).
func TestScenario_I18N_005_DefaultLocaleFallback(t *testing.T) {
	t.Parallel()

	p := testkit.NewProvider(t)
	env := fetchI18nPrompt(t, p, "", "", "")
	if got, _ := env["locale"].(string); got != "en" {
		t.Errorf("prompt.locale = %v, want en (default fall-back)", env["locale"])
	}
}

// TestScenario_I18N_010_PromptCarriesResolvedLocale pins the prompt
// envelope contract: the OP-resolved locale rides on the `locale`
// field every time the resolver is wired.
//
// Spec: SPA prompt envelope (file header).
func TestScenario_I18N_010_PromptCarriesResolvedLocale(t *testing.T) {
	t.Parallel()

	p := testkit.NewProvider(t)
	env := fetchI18nPrompt(t, p, "ja", "", "")
	got, ok := env["locale"].(string)
	if !ok || got == "" {
		t.Fatalf("prompt.locale missing: %v", env["locale"])
	}
	if got != "ja" {
		t.Errorf("prompt.locale = %q, want ja", got)
	}
}

// TestScenario_I18N_011_PromptEchoesUILocalesHint pins the prompt
// envelope contract: the RP's ui_locales parameter rides on the
// envelope as `ui_locales_hint`, in caller-supplied order.
//
// Spec: SPA prompt envelope (file header).
func TestScenario_I18N_011_PromptEchoesUILocalesHint(t *testing.T) {
	t.Parallel()

	p := testkit.NewProvider(t)
	env := fetchI18nPrompt(t, p, "ja en", "", "")
	hint, ok := env["ui_locales_hint"].([]any)
	if !ok || len(hint) != 2 {
		t.Fatalf("ui_locales_hint missing or wrong length: %v", env["ui_locales_hint"])
	}
	if hint[0] != "ja" || hint[1] != "en" {
		t.Errorf("ui_locales_hint = %v, want [ja en] (caller order)", hint)
	}
}

// TestScenario_I18N_012_PromptListsAvailableLocales pins the prompt
// envelope contract: the `locales_available` field equals the
// registered locale list (and the discovery `ui_locales_supported`
// value) so SPAs can build a language picker without re-fetching
// discovery.
//
// Spec: OIDC Discovery §3 / SPA prompt envelope (file header).
func TestScenario_I18N_012_PromptListsAvailableLocales(t *testing.T) {
	t.Parallel()

	p := testkit.NewProvider(t)
	env := fetchI18nPrompt(t, p, "", "", "")
	avail, ok := env["locales_available"].([]any)
	if !ok || len(avail) != 2 {
		t.Fatalf("locales_available missing or wrong length: %v", env["locales_available"])
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
		t.Errorf("locales_available = %v, want en + ja (seed catalogue)", avail)
	}
}

// TestScenario_I18N_013_LocaleFieldsOmitWhenResolverAbsent pins the
// omit-when-empty half of the prompt envelope contract: when no
// resolver is wired (unit tests, embedders without i18n) the locale
// fields stay off the wire so pre-existing SPAs keep working.
//
// Spec: SPA prompt envelope (file header).
func TestScenario_I18N_013_LocaleFieldsOmitWhenResolverAbsent(t *testing.T) {
	t.Parallel()

	// The resolver is wired through op.New unconditionally, so this
	// row is exercised at the JSON tag level rather than through a
	// live handler. The guard rail is the omitempty tag on
	// interaction.Prompt.Locale / UILocalesHint / LocalesAvailable;
	// dropping the tag would land on
	// op/interaction/types_test.go's TestPrompt_LocaleFieldsOmitWhenEmpty
	// before reaching this row. The scenarios catalog still binds the
	// behaviour so a future regression is logged here too.
	t.Log("guarded by op/interaction/types_test.go TestPrompt_LocaleFieldsOmitWhenEmpty")
}

// TestScenario_I18N_020_SetLocaleCookiePersistsTheSelection pins the
// locale-switch UX contract end to end: what op.Provider.SetLocaleCookie
// writes is what chain step 3 reads back on the next authorize hit.
//
// The round trip is the point. The writer normalises ("ja-JP" → the
// registered "ja") and the reader validates the cookie before matching
// it, so a writer that emitted the raw request tag, or attributes the
// browser would refuse to return, would leave both halves individually
// green and the feature broken. Asserting the cookie's shape alone
// cannot catch that; only feeding the emitted cookie back through
// /authorize can.
//
// Spec: locale switch UX (catalog I18N-020) / locale resolution chain
// (file header).
func TestScenario_I18N_020_SetLocaleCookiePersistsTheSelection(t *testing.T) {
	t.Parallel()

	p := testkit.NewProvider(t)

	rec := httptest.NewRecorder()
	if err := p.OP.SetLocaleCookie(rec, "ja-JP"); err != nil {
		t.Fatalf("SetLocaleCookie(ja-JP): %v", err)
	}
	written := rec.Result().Cookies()
	if len(written) != 1 {
		t.Fatalf("SetLocaleCookie wrote %d cookies, want 1", len(written))
	}
	got := written[0]
	if got.Name != "__Host-oidc_locale" {
		t.Errorf("cookie name = %q, want __Host-oidc_locale", got.Name)
	}
	if got.Value != "ja" {
		t.Errorf("cookie value = %q, want ja (the registered tag ja-JP matches)", got.Value)
	}
	if !got.HttpOnly || !got.Secure || got.SameSite != http.SameSiteLaxMode || got.Path != "/" {
		t.Errorf(
			"cookie attributes = HttpOnly:%v Secure:%v SameSite:%v Path:%q; want true/true/Lax/\"/\"",
			got.HttpOnly, got.Secure, got.SameSite, got.Path,
		)
	}
	if got.MaxAge != int((365 * 24 * time.Hour).Seconds()) {
		t.Errorf("cookie MaxAge = %d, want one year in seconds", got.MaxAge)
	}

	// Accept-Language deliberately disagrees: if the cookie were
	// ignored the prompt would come back "en" and the assertion would
	// not be able to tell a working cookie from a default fall-back.
	env := fetchI18nPrompt(t, p, "", got.Value, "en-US")
	if resolved, _ := env["locale"].(string); resolved != "ja" {
		t.Errorf("prompt.locale = %v after SetLocaleCookie(ja-JP), want ja", env["locale"])
	}
}

// TestScenario_I18N_020_SetLocaleCookieRejectsUnregistered pins the
// other half of the row: a locale the resolver would skip is refused at
// the write, not stored. Persisting it would leave a picker that
// reports success and never changes the language, because chain step 3
// silently drops an unmatched cookie.
//
// Spec: locale switch UX (catalog I18N-020).
func TestScenario_I18N_020_SetLocaleCookieRejectsUnregistered(t *testing.T) {
	t.Parallel()

	p := testkit.NewProvider(t)

	rec := httptest.NewRecorder()
	err := p.OP.SetLocaleCookie(rec, "zz")
	if !errors.Is(err, op.ErrLocaleNotRegistered) {
		t.Fatalf("SetLocaleCookie(zz) error = %v, want ErrLocaleNotRegistered", err)
	}
	if cookies := rec.Result().Cookies(); len(cookies) != 0 {
		t.Errorf("rejected locale still wrote %d cookies", len(cookies))
	}
}

// TestScenario_I18N_020_ClearLocaleCookieRestoresTheChain pins the
// "use my browser's language" path: clearing the cookie hands the
// decision back to the lower chain steps.
//
// Spec: locale switch UX (catalog I18N-020).
func TestScenario_I18N_020_ClearLocaleCookieRestoresTheChain(t *testing.T) {
	t.Parallel()

	p := testkit.NewProvider(t)

	rec := httptest.NewRecorder()
	p.OP.ClearLocaleCookie(rec)
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("ClearLocaleCookie wrote %d cookies, want 1", len(cookies))
	}
	if cookies[0].Name != "__Host-oidc_locale" || cookies[0].Value != "" || cookies[0].MaxAge >= 0 {
		t.Errorf(
			"clear cookie = %q=%q MaxAge=%d, want __Host-oidc_locale empty with a negative MaxAge",
			cookies[0].Name, cookies[0].Value, cookies[0].MaxAge,
		)
	}

	// With no cookie the chain drops to Accept-Language, which is what
	// the picker's "auto" entry is asking for.
	env := fetchI18nPrompt(t, p, "", "", "ja-JP,en;q=0.7")
	if resolved, _ := env["locale"].(string); resolved != "ja" {
		t.Errorf("prompt.locale = %v with the cookie cleared, want ja from Accept-Language", env["locale"])
	}
}

// TestScenario_I18N_030_LocaleBundleJSONEndpoint is OOS — see catalog out_of_scope_reason.
func TestScenario_I18N_030_LocaleBundleJSONEndpoint(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: I18N-030 (see catalog out_of_scope_reason)")
}
