//nolint:testpackage // white-box: renderBrowserError and acceptQuality are unexported.
package authorizeendpoint

import (
	"context"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op/interaction"
)

// TestRenderBrowserError_FallsBackToJSON_WhenAcceptIsAbsent confirms
// that XHR / cURL / fetch() callers (which usually omit Accept or send
// "*/*") keep their existing JSON envelope even after the negotiating
// helper landed.
func TestRenderBrowserError_FallsBackToJSON_WhenAcceptIsAbsent(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/oidc/auth", nil)
	renderBrowserError(rec, req, interaction.HTMLDriver{}, http.StatusBadRequest, "invalid_request", "no Accept", "")
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type=%q want application/json (no Accept must default to JSON)", got)
	}
	if got := rec.Code; got != http.StatusBadRequest {
		t.Errorf("status=%d want 400", got)
	}
}

// TestRenderBrowserError_PrefersHTML_WhenBrowserNavigates covers the
// canonical browser case: Accept advertises text/html with priority
// over application/json. The helper picks the HTML path so OFCS-style
// reviewers see an actual error page rather than a JSON envelope.
func TestRenderBrowserError_PrefersHTML_WhenBrowserNavigates(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/oidc/auth", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	renderBrowserError(rec, req, interaction.HTMLDriver{}, http.StatusBadRequest, "invalid_request_uri", "expired", "abc")

	ct := rec.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type=%q want text/html", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `data-code="invalid_request_uri"`) {
		t.Errorf("HTML body missing data-code attribute\n%s", body)
	}
}

// TestRenderBrowserError_StaysJSON_WhenJSONHasHigherQ verifies the
// q-value tiebreak: a client that explicitly asks for JSON over HTML
// (Accept: application/json;q=1, text/html;q=0.5) keeps the JSON
// envelope, which matches what an SPA's fetch() typically requests.
func TestRenderBrowserError_StaysJSON_WhenJSONHasHigherQ(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/oidc/auth", nil)
	req.Header.Set("Accept", "application/json,text/html;q=0.5")
	renderBrowserError(rec, req, interaction.HTMLDriver{}, http.StatusBadRequest, "invalid_request", "param missing", "")

	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type=%q want application/json", got)
	}
}

// TestRenderBrowserError_FallsBackToJSON_WhenDriverLacksErrorRenderer
// confirms the additive-interface contract: an embedder Driver that
// satisfies only the legacy Driver interface (no RenderError) does not
// crash and does not gain HTML — the response is the canonical JSON
// envelope, identical to the pre-feature behaviour.
func TestRenderBrowserError_FallsBackToJSON_WhenDriverLacksErrorRenderer(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/oidc/auth", nil)
	req.Header.Set("Accept", "text/html")

	renderBrowserError(rec, req, legacyDriverNoErrorRenderer{}, http.StatusBadRequest, "invalid_request", "no", "")
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type=%q want application/json (legacy driver has no RenderError)", got)
	}
}

// legacyDriverNoErrorRenderer satisfies Driver but not ErrorRenderer.
// It models an embedder that wrote a Driver before the ErrorRenderer
// contract existed; the negotiation helper must fall back to JSON
// rather than panic or attempt a method that doesn't exist.
type legacyDriverNoErrorRenderer struct{}

func (legacyDriverNoErrorRenderer) Render(_ http.ResponseWriter, _ *http.Request, _ interaction.Prompt) error {
	return nil
}

func (legacyDriverNoErrorRenderer) ParseSubmission(_ *http.Request) (interaction.FormSubmission, error) {
	return interaction.FormSubmission{}, nil
}

// TestAcceptQuality covers the parser corner cases: q-value parsing,
// case-insensitive media type, multiple entries.
func TestAcceptQuality(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		header string
		target string
		wantQ  float64
		wantOk bool
	}{
		{"absent", "application/json", "text/html", 0, false},
		{"plain", "text/html", "text/html", 1.0, true},
		{"with q", "text/html;q=0.5", "text/html", 0.5, true},
		{"case insensitive", "TEXT/HTML", "text/html", 1.0, true},
		{"multi-entry first", "application/json,text/html;q=0.5", "application/json", 1.0, true},
		{"multi-entry second", "application/json,text/html;q=0.5", "text/html", 0.5, true},
		{"wildcard ignored", "*/*", "text/html", 0, false},
		{"text-wildcard ignored", "text/*", "text/html", 0, false},
		{"malformed q ignored", "text/html;q=foo", "text/html", 1.0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gotQ, gotOk := acceptQuality(tc.header, tc.target)
			if gotOk != tc.wantOk {
				t.Errorf("ok=%v want %v", gotOk, tc.wantOk)
			}
			if gotQ != tc.wantQ {
				t.Errorf("q=%v want %v", gotQ, tc.wantQ)
			}
		})
	}
}

// TestRenderBrowserError_KeepsHTMLThroughTemplateOverlay pins the
// configuration the library builds for itself: an embedder who supplies
// a consent or chooser template gets the built-in HTML driver wrapped in
// interaction.TemplateOverlayDriver. Adding a branding template must not
// change what a browser sees when the authorization request fails before
// a redirect target can be trusted — that failure is the one the user
// reads on the OP's own origin.
func TestRenderBrowserError_KeepsHTMLThroughTemplateOverlay(t *testing.T) {
	t.Parallel()

	driver := interaction.TemplateOverlayDriver{
		Inner: interaction.HTMLDriver{},
		ConsentTemplate: template.Must(template.New("consent").
			Parse(`<!doctype html><html><body>branded consent</body></html>`)),
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/oidc/auth", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	renderBrowserError(rec, req, driver, http.StatusBadRequest, "invalid_request_uri", "expired", "st-1")

	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "text/html") {
		t.Fatalf("Content-Type=%q want text/html (the overlay must not drop the inner ErrorRenderer)", got)
	}
	if body := rec.Body.String(); !strings.Contains(body, `data-code="invalid_request_uri"`) {
		t.Errorf("HTML body missing the inner driver's error markup\n%s", body)
	}
}

// TestRenderBrowserError_OverlayOverLegacyDriverStaysJSON confirms the
// wrapper does not manufacture an error surface the wrapped Driver never
// had: an embedder whose Driver predates the ErrorRenderer contract
// keeps the JSON envelope after adding a template, exactly as before.
func TestRenderBrowserError_OverlayOverLegacyDriverStaysJSON(t *testing.T) {
	t.Parallel()

	driver := interaction.TemplateOverlayDriver{Inner: legacyDriverNoErrorRenderer{}}

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/oidc/auth", nil)
	req.Header.Set("Accept", "text/html")
	renderBrowserError(rec, req, driver, http.StatusBadRequest, "invalid_request", "no", "")

	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type=%q want application/json", got)
	}
}

// TestRenderBrowserError_StampsCeremonyHeaders covers the pre-redirect
// error page for a Driver that stamps nothing of its own. The framing,
// sniffing and referrer protections belong to the endpoint precisely so
// that a Driver the library did not write cannot lose them.
func TestRenderBrowserError_StampsCeremonyHeaders(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/oidc/auth", nil)
	req.Header.Set("Accept", "text/html")
	renderBrowserError(rec, req, legacyDriverNoErrorRenderer{}, http.StatusBadRequest, "invalid_request", "no", "")

	for header, want := range map[string]string{
		"X-Frame-Options":        "DENY",
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "same-origin",
	} {
		if got := rec.Header().Get(header); got != want {
			t.Errorf("%s=%q want %q", header, got, want)
		}
	}
}
