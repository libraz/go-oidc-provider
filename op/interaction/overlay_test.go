package interaction_test

import (
	"context"
	"errors"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op/interaction"
)

// recordingDriver is a stub [interaction.Driver] used to verify that
// TemplateOverlayDriver delegates to its inner Driver in the expected
// dispatch paths.
type recordingDriver struct {
	renderCalls          int
	parseSubmissionCalls int
	parseSubmissionRet   interaction.FormSubmission
	parseSubmissionErr   error
	renderErr            error
}

func (d *recordingDriver) Render(_ http.ResponseWriter, _ *http.Request, _ interaction.Prompt) error {
	d.renderCalls++
	return d.renderErr
}

func (d *recordingDriver) ParseSubmission(_ *http.Request) (interaction.FormSubmission, error) {
	d.parseSubmissionCalls++
	return d.parseSubmissionRet, d.parseSubmissionErr
}

// TestTemplateOverlay_PassthroughUnknownPromptType confirms that a
// prompt whose payload is not one of the two well-known overlay types
// is delegated to the inner Driver, regardless of whether the
// templates are wired.
func TestTemplateOverlay_PassthroughUnknownPromptType(t *testing.T) {
	t.Parallel()

	prompt := interaction.Prompt{
		Type:     "auth.password",
		Data:     interaction.PasswordPromptData{UsernameHint: "alice"},
		Inputs:   []interaction.FieldSpec{{Name: "username", Kind: interaction.FieldText, Required: true}},
		StateRef: "ref-pw",
	}

	innerRec := httptest.NewRecorder()
	innerReq := httptest.NewRequestWithContext(context.Background(), "GET", "/oidc/interaction/u-1", nil)
	if err := (interaction.HTMLDriver{}).Render(innerRec, innerReq, prompt); err != nil {
		t.Fatalf("inner Render: %v", err)
	}
	wantBody := innerRec.Body.String()

	overlay := interaction.TemplateOverlayDriver{Inner: interaction.HTMLDriver{}}
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/oidc/interaction/u-1", nil)
	if err := overlay.Render(rec, req, prompt); err != nil {
		t.Fatalf("overlay Render: %v", err)
	}
	if rec.Body.String() != wantBody {
		t.Errorf("overlay output diverges from inner HTMLDriver:\nwant:\n%s\n\ngot:\n%s", wantBody, rec.Body.String())
	}
}

// TestTemplateOverlay_PassthroughConsentNilTemplate confirms that a
// consent prompt is delegated to the inner Driver when ConsentTemplate
// is nil.
func TestTemplateOverlay_PassthroughConsentNilTemplate(t *testing.T) {
	t.Parallel()

	prompt := interaction.Prompt{
		Type: "consent.scope",
		Data: interaction.ConsentScopePromptData{
			Scopes: []interaction.ConsentScope{{Name: "openid", Required: true}},
		},
		StateRef: "ref-c",
	}

	innerRec := httptest.NewRecorder()
	innerReq := httptest.NewRequestWithContext(context.Background(), "GET", "/oidc/interaction/u-1", nil)
	if err := (interaction.HTMLDriver{}).Render(innerRec, innerReq, prompt); err != nil {
		t.Fatalf("inner Render: %v", err)
	}
	wantBody := innerRec.Body.String()

	overlay := interaction.TemplateOverlayDriver{Inner: interaction.HTMLDriver{}}
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/oidc/interaction/u-1", nil)
	if err := overlay.Render(rec, req, prompt); err != nil {
		t.Fatalf("overlay Render: %v", err)
	}
	if rec.Body.String() != wantBody {
		t.Errorf("overlay output diverges from inner HTMLDriver when ConsentTemplate is nil")
	}
}

// TestTemplateOverlay_OverrideConsentRendersTemplate confirms that a
// non-nil ConsentTemplate replaces the inner Driver's consent surface.
func TestTemplateOverlay_OverrideConsentRendersTemplate(t *testing.T) {
	t.Parallel()

	tmpl := template.Must(template.New("consent").Parse(
		`<!doctype html><html><body><h1>{{.Client.Name}}</h1>` +
			`<form method="{{.SubmitMethod}}" action="{{.SubmitAction}}">` +
			`<input type="hidden" name="state_ref" value="{{.StateRef}}">` +
			`<input type="hidden" name="csrf_token" value="{{.CSRFToken}}">` +
			`<ul>{{range .Scopes}}<li>{{.Name}}</li>{{end}}</ul>` +
			`<input type="hidden" name="{{.ApprovedScopesField}}" value="">` +
			`</form></body></html>`))
	overlay := interaction.TemplateOverlayDriver{
		Inner:           interaction.HTMLDriver{},
		ConsentTemplate: tmpl,
	}

	prompt := interaction.Prompt{
		Type: "consent.scope",
		Data: interaction.ConsentScopePromptData{
			Client: interaction.ClientView{ClientID: "rp-1", Name: "Acme"},
			Scopes: []interaction.ConsentScope{
				{Name: "openid", Required: true},
				{Name: "profile"},
			},
		},
		StateRef:  "ref-consent",
		CSRFToken: "csrf-1",
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/oidc/interaction/u-1", nil)
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

	body := rec.Body.String()
	for _, want := range []string{
		"<h1>Acme</h1>",
		`name="state_ref" value="ref-consent"`,
		`name="csrf_token" value="csrf-1"`,
		"<li>openid</li>",
		"<li>profile</li>",
		`name="approved_scopes"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("rendered body missing %q\n--- body ---\n%s", want, body)
		}
	}
	// Confirm the overlay did not also write the HTMLDriver fallback
	// markup. The HTMLDriver consent intro renders an <ul> too, but its
	// signature includes a "(required)" suffix on required scopes,
	// which the custom template above intentionally omits.
	if strings.Contains(body, "(required)") {
		t.Errorf("rendered body contains HTMLDriver fallback markup\n--- body ---\n%s", body)
	}
}

// TestTemplateOverlay_OverrideChooserRendersTemplate confirms that a
// non-nil ChooserTemplate replaces the inner Driver's chooser surface.
func TestTemplateOverlay_OverrideChooserRendersTemplate(t *testing.T) {
	t.Parallel()

	tmpl := template.Must(template.New("chooser").Parse(
		`<!doctype html><html><body>` +
			`<form method="{{.SubmitMethod}}" action="{{.SubmitAction}}">` +
			`<input type="hidden" name="state_ref" value="{{.StateRef}}">` +
			`<input type="hidden" name="csrf_token" value="{{.CSRFToken}}">` +
			`<ul>{{range .Accounts}}<li>{{.Subject}}</li>{{end}}</ul>` +
			`<a href="{{.AddAccountURL}}">add</a>` +
			`<input type="hidden" name="{{.SessionIDField}}" value="">` +
			`</form></body></html>`))
	overlay := interaction.TemplateOverlayDriver{
		Inner:           interaction.HTMLDriver{},
		ChooserTemplate: tmpl,
	}

	prompt := interaction.Prompt{
		Type: "interaction.chooser",
		Data: interaction.ChooserPromptData{
			Accounts: []interaction.ChooserAccount{
				{SessionID: "s-1", Subject: "alice"},
				{SessionID: "s-2", Subject: "bob"},
			},
			AddAccountURL: "/authorize?prompt=login",
		},
		StateRef:  "ref-chooser",
		CSRFToken: "csrf-2",
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/oidc/interaction/u-2", nil)
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

	body := rec.Body.String()
	for _, want := range []string{
		"<li>alice</li>",
		"<li>bob</li>",
		`name="state_ref" value="ref-chooser"`,
		`name="csrf_token" value="csrf-2"`,
		`href="/authorize?prompt=login"`,
		`name="session_id"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("rendered body missing %q\n--- body ---\n%s", want, body)
		}
	}
}

// TestTemplateOverlay_TemplateExecutionErrorDoesNotCommitResponse
// confirms template execution errors surface before response headers or
// a partial body are written. The authorize endpoint can then treat the
// render as failed instead of leaking a broken 200 HTML response.
func TestTemplateOverlay_TemplateExecutionErrorDoesNotCommitResponse(t *testing.T) {
	t.Parallel()

	tmpl := template.Must(template.New("consent").
		Option("missingkey=error").
		Parse(`before {{.MissingField}} after`))
	overlay := interaction.TemplateOverlayDriver{
		Inner:           interaction.HTMLDriver{},
		ConsentTemplate: tmpl,
	}

	rec := &commitRecorder{header: make(http.Header)}
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/oidc/interaction/u-1", nil)
	prompt := interaction.Prompt{
		Type: "consent.scope",
		Data: interaction.ConsentScopePromptData{},
	}
	err := overlay.Render(rec, req, prompt)
	if err == nil {
		t.Fatal("Render error = nil, want template execution error")
	}
	if rec.status != 0 {
		t.Errorf("status committed = %d, want 0", rec.status)
	}
	if rec.body.String() != "" {
		t.Errorf("body committed = %q, want empty", rec.body.String())
	}
	if got := rec.header.Get("Content-Type"); got != "" {
		t.Errorf("Content-Type = %q, want empty before successful render", got)
	}
}

// TestTemplateOverlay_InnerNilRender confirms that Render returns
// [interaction.ErrTemplateOverlayInnerNil] when dispatch falls through
// to a nil Inner.
func TestTemplateOverlay_InnerNilRender(t *testing.T) {
	t.Parallel()

	overlay := interaction.TemplateOverlayDriver{}
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/oidc/interaction/u-1", nil)
	prompt := interaction.Prompt{
		Type: "consent.scope",
		Data: interaction.ConsentScopePromptData{},
	}
	err := overlay.Render(rec, req, prompt)
	if !errors.Is(err, interaction.ErrTemplateOverlayInnerNil) {
		t.Fatalf("err = %v, want ErrTemplateOverlayInnerNil", err)
	}
}

// TestTemplateOverlay_InnerNilParseSubmission confirms that
// ParseSubmission also surfaces the inner-nil sentinel.
func TestTemplateOverlay_InnerNilParseSubmission(t *testing.T) {
	t.Parallel()

	overlay := interaction.TemplateOverlayDriver{}
	r := httptest.NewRequestWithContext(context.Background(), "POST", "/oidc/interaction/u-1", strings.NewReader(""))
	_, err := overlay.ParseSubmission(r)
	if !errors.Is(err, interaction.ErrTemplateOverlayInnerNil) {
		t.Fatalf("err = %v, want ErrTemplateOverlayInnerNil", err)
	}
}

// TestTemplateOverlay_ParseSubmissionDelegated confirms that the
// wrapper invokes the inner Driver's ParseSubmission exactly once and
// passes its return values through unchanged.
func TestTemplateOverlay_ParseSubmissionDelegated(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("inner parse error")
	wantSub := interaction.FormSubmission{StateRef: "ref-x", Values: map[string]string{"k": "v"}}
	inner := &recordingDriver{parseSubmissionRet: wantSub, parseSubmissionErr: wantErr}
	overlay := interaction.TemplateOverlayDriver{Inner: inner}

	r := httptest.NewRequestWithContext(context.Background(), "POST", "/oidc/interaction/u-1", strings.NewReader(""))
	got, err := overlay.ParseSubmission(r)
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want %v", err, wantErr)
	}
	if got.StateRef != wantSub.StateRef {
		t.Errorf("StateRef = %q, want %q", got.StateRef, wantSub.StateRef)
	}
	if got.Values["k"] != "v" {
		t.Errorf("Values[k] = %q, want v", got.Values["k"])
	}
	if inner.parseSubmissionCalls != 1 {
		t.Errorf("inner ParseSubmission calls = %d, want 1", inner.parseSubmissionCalls)
	}
}

// TestTemplateOverlay_SubmissionFieldConstants is a cheap regression
// guard against an accidental rename of the form field names the
// built-in consent and chooser interactions consume.
func TestTemplateOverlay_SubmissionFieldConstants(t *testing.T) {
	t.Parallel()

	if interaction.ConsentApprovedScopesField != "approved_scopes" {
		t.Errorf("ConsentApprovedScopesField = %q, want approved_scopes", interaction.ConsentApprovedScopesField)
	}
	if interaction.ChooserSessionIDField != "session_id" {
		t.Errorf("ChooserSessionIDField = %q, want session_id", interaction.ChooserSessionIDField)
	}
}

// TestTemplateOverlay_SubmitActionReflectsRequestURL confirms that the
// rendered SubmitAction value mirrors the inbound request URI exactly,
// including query parameters.
func TestTemplateOverlay_SubmitActionReflectsRequestURL(t *testing.T) {
	t.Parallel()

	tmpl := template.Must(template.New("consent").Parse(`ACTION={{.SubmitAction}};METHOD={{.SubmitMethod}}`))
	overlay := interaction.TemplateOverlayDriver{
		Inner:           interaction.HTMLDriver{},
		ConsentTemplate: tmpl,
	}
	prompt := interaction.Prompt{
		Type: "consent.scope",
		Data: interaction.ConsentScopePromptData{},
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), "GET", "/oidc/interaction/abc?step=1", nil)
	if err := overlay.Render(rec, req, prompt); err != nil {
		t.Fatalf("overlay Render: %v", err)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "ACTION=/oidc/interaction/abc?step=1") {
		t.Errorf("SubmitAction not reflected in body: %s", body)
	}
	if !strings.Contains(body, "METHOD=POST") {
		t.Errorf("SubmitMethod = POST not in body: %s", body)
	}
}

type commitRecorder struct {
	header http.Header
	status int
	body   strings.Builder
}

func (r *commitRecorder) Header() http.Header {
	return r.header
}

func (r *commitRecorder) WriteHeader(status int) {
	r.status = status
}

func (r *commitRecorder) Write(p []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.body.Write(p)
}
