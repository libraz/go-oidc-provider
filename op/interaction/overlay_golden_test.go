package interaction_test

import (
	"bytes"
	"context"
	"flag"
	"html/template"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/op/interaction"
)

// updateOverlayGoldens regenerates the testdata/overlay/*.golden.html
// fixtures when set. Run "go test -update ./op/interaction/..." after a
// deliberate change to the overlay rendering and commit the regen.
//
// The flag is named distinctly from htmldriver_test.go's [updateGoldens]
// so the two suites can be regenerated independently if a future change
// touches only one of them; today the same -update flag drives both
// because Go's flag package shares a process-wide registry.
var updateOverlayGoldens = flag.Bool("update-overlay", false, "update TemplateOverlayDriver golden files")

// consentOverlayTemplate is the inline minimal consent template the
// golden harness pins. The body intentionally exercises every field of
// [interaction.ConsentTemplateData] (Client, Scopes, StateRef,
// CSRFToken, ApprovedScopesField, SubmitMethod, SubmitAction) so a
// future widening of the struct surfaces in the diff against the
// fixture before it ships.
const consentOverlayTemplate = `<!doctype html><html><body>
<h1>Authorize {{.Client.Name}}</h1>
<form method="{{.SubmitMethod}}" action="{{.SubmitAction}}">
<input type="hidden" name="state_ref" value="{{.StateRef}}">
<input type="hidden" name="csrf_token" value="{{.CSRFToken}}">
{{range .Scopes}}{{if .Required}}<input type="hidden" name="{{$.ApprovedScopesField}}" value="{{.Name}}">{{end}}<label><input type="checkbox" name="{{$.ApprovedScopesField}}" value="{{.Name}}"{{if .Required}} checked disabled{{end}}> {{.Description}}</label>{{end}}
<button type="submit">Approve</button>
</form>
</body></html>`

// chooserOverlayTemplate is the inline minimal chooser template the
// golden harness pins. The second account row in the fixture
// deliberately omits DisplayName so the {{if .DisplayName}}{{else}}
// branch is exercised; the AddAccountURL anchor is unconditional so
// the fixture also pins the post-loop tail.
const chooserOverlayTemplate = `<!doctype html><html><body>
<h1>Choose an account</h1>
{{range .Accounts}}<form method="{{$.SubmitMethod}}" action="{{$.SubmitAction}}"><input type="hidden" name="state_ref" value="{{$.StateRef}}"><input type="hidden" name="{{$.SessionIDField}}" value="{{.SessionID}}"><button type="submit">{{if .DisplayName}}{{.DisplayName}}{{else}}{{.Subject}}{{end}}</button></form>{{end}}
<a href="{{.AddAccountURL}}">Sign in to a different account</a>
</body></html>`

// TestTemplateOverlay_GoldenConsent pins the byte output of
// TemplateOverlayDriver.Render against a fixed consent prompt fixture.
// Inputs are deterministic (no clocks, no random) so any drift in the
// overlay's data projection or header stamping surfaces as a diff.
func TestTemplateOverlay_GoldenConsent(t *testing.T) {
	t.Parallel()

	tmpl := template.Must(template.New("consent").Parse(consentOverlayTemplate))
	overlay := interaction.TemplateOverlayDriver{
		Inner:           interaction.HTMLDriver{},
		ConsentTemplate: tmpl,
	}
	// Deterministic fixture values; "csrf-FIXED" / "state-ref-FIXED" are
	// inert string literals, not real credentials. The gosec G101 false
	// positive is suppressed because the strings are pinned by the
	// adjacent golden fixture.
	prompt := interaction.Prompt{ //nolint:gosec // golden-test fixture, no real credentials
		Type: "consent.scope",
		Data: interaction.ConsentScopePromptData{
			Client: interaction.ClientView{
				ClientID:  "client-1",
				Name:      "Demo Client",
				LogoURL:   "https://example.test/logo.png",
				ClientURI: "https://example.test/",
				PolicyURI: "https://example.test/privacy",
				TosURI:    "https://example.test/tos",
			},
			Scopes: []interaction.ConsentScope{
				{Name: "openid", Required: true, Description: "Sign you in"},
				{Name: "profile", Description: "Your profile"},
				{Name: "email", Description: "Your email"},
			},
		},
		StateRef:  "state-ref-FIXED",
		CSRFToken: "csrf-FIXED",
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), "GET",
		"/oidc/interaction/abc?step=1", nil)
	if err := overlay.Render(rec, req, prompt); err != nil {
		t.Fatalf("overlay Render: %v", err)
	}

	if got := rec.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want text/html; charset=utf-8", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store, no-cache, must-revalidate" {
		t.Errorf("Cache-Control = %q, want no-store, no-cache, must-revalidate", got)
	}
	if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options = %q, want DENY", got)
	}

	path := filepath.Join("testdata", "overlay", "consent.golden.html")
	checkOverlayGolden(t, path, rec.Body.Bytes())
}

// TestTemplateOverlay_GoldenChooser pins the byte output of
// TemplateOverlayDriver.Render against a fixed chooser prompt fixture.
// AuthTime values are seeded to a fixed UTC instant so the fixture
// stays stable across runs even though the template above does not
// emit them — the field is asserted only via the deterministic input
// surface.
func TestTemplateOverlay_GoldenChooser(t *testing.T) {
	t.Parallel()

	tmpl := template.Must(template.New("chooser").Parse(chooserOverlayTemplate))
	overlay := interaction.TemplateOverlayDriver{
		Inner:           interaction.HTMLDriver{},
		ChooserTemplate: tmpl,
	}
	authTime := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)
	prompt := interaction.Prompt{ //nolint:gosec // golden-test fixture, no real credentials
		Type: "interaction.chooser",
		Data: interaction.ChooserPromptData{
			Accounts: []interaction.ChooserAccount{
				{SessionID: "sess-A", Subject: "alice", DisplayName: "Alice", AuthTime: authTime},
				{SessionID: "sess-B", Subject: "bob", AuthTime: authTime},
			},
			AddAccountURL: "/oidc/auth?prompt=login",
		},
		StateRef:  "state-ref-FIXED",
		CSRFToken: "csrf-FIXED",
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), "GET",
		"/oidc/interaction/abc?step=1", nil)
	if err := overlay.Render(rec, req, prompt); err != nil {
		t.Fatalf("overlay Render: %v", err)
	}

	if got := rec.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
		t.Errorf("Content-Type = %q, want text/html; charset=utf-8", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store, no-cache, must-revalidate" {
		t.Errorf("Cache-Control = %q, want no-store, no-cache, must-revalidate", got)
	}
	if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options = %q, want DENY", got)
	}

	path := filepath.Join("testdata", "overlay", "chooser.golden.html")
	checkOverlayGolden(t, path, rec.Body.Bytes())
}

// checkOverlayGolden compares got against the fixture at path. The
// helper mirrors htmldriver_test.go's golden idiom: when -update or
// -update-overlay is set the fixture is regenerated (with a single
// trailing newline appended for POSIX compliance); otherwise the read
// fixture is trimmed of its trailing newline before the byte compare.
func checkOverlayGolden(t *testing.T, path string, got []byte) {
	t.Helper()
	if *updateOverlayGoldens || *updateGoldens {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		payload := append(append([]byte{}, got...), '\n')
		if err := os.WriteFile(path, payload, 0o644); err != nil { //nolint:gosec // golden files are world-readable test fixtures.
			t.Fatalf("WriteFile %s: %v", path, err)
		}
		return
	}
	want, err := os.ReadFile(path) //nolint:gosec // golden path is fixed under testdata/.
	if err != nil {
		t.Fatalf("ReadFile %s: %v (run with -update to regenerate)", path, err)
	}
	want = bytes.TrimRight(want, "\n")
	if !bytes.Equal(got, want) {
		t.Errorf("golden mismatch for %s\n--- want ---\n%s\n--- got ---\n%s", path, want, got)
	}
}
