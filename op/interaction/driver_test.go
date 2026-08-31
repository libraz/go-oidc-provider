package interaction_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op/interaction"
)

func TestJSONDriver_RenderEmitsJSONEnvelope(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	prompt := interaction.Prompt{
		Type:     "auth.password",
		Data:     interaction.PasswordPromptData{UsernameHint: "alice"},
		Inputs:   []interaction.FieldSpec{{Name: "password", Kind: interaction.FieldPassword, Required: true}},
		StateRef: "ref-1",
	}
	if err := (interaction.JSONDriver{}).Render(rec, httptest.NewRequestWithContext(context.Background(), "GET", "/interaction/u-1", nil), prompt); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	var got struct {
		Type     string `json:"type"`
		StateRef string `json:"state_ref"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Type != prompt.Type || got.StateRef != prompt.StateRef {
		t.Errorf("envelope = %+v, want type=%s state_ref=%s", got, prompt.Type, prompt.StateRef)
	}
}

func TestJSONDriver_ParseSubmissionDecodesEnvelope(t *testing.T) {
	t.Parallel()

	body := `{"state_ref":"ref-1","values":{"password":"hunter2"}}`
	r := httptest.NewRequestWithContext(context.Background(), "POST", "/interaction/u-1", strings.NewReader(body))
	sub, err := (interaction.JSONDriver{}).ParseSubmission(r)
	if err != nil {
		t.Fatalf("ParseSubmission: %v", err)
	}
	if sub.StateRef != "ref-1" {
		t.Errorf("StateRef = %q, want ref-1", sub.StateRef)
	}
	if sub.Values["password"] != "hunter2" {
		t.Errorf("Values[password] = %q, want hunter2", sub.Values["password"])
	}
}

func TestJSONDriver_ParseSubmissionRejectsUnknownFields(t *testing.T) {
	t.Parallel()

	body := `{"state_ref":"ref-1","values":{},"extra":"reject"}`
	r := httptest.NewRequestWithContext(context.Background(), "POST", "/interaction/u-1", strings.NewReader(body))
	_, err := (interaction.JSONDriver{}).ParseSubmission(r)
	if !errors.Is(err, interaction.ErrSubmissionMalformed) {
		t.Fatalf("err = %v, want ErrSubmissionMalformed", err)
	}
}

func TestJSONDriver_ParseSubmissionRejectsEmptyBody(t *testing.T) {
	t.Parallel()

	r := httptest.NewRequestWithContext(context.Background(), "POST", "/interaction/u-1", bytes.NewReader(nil))
	_, err := (interaction.JSONDriver{}).ParseSubmission(r)
	if !errors.Is(err, interaction.ErrSubmissionMalformed) {
		t.Fatalf("err = %v, want ErrSubmissionMalformed", err)
	}
}

// TestJSONDriver_ParseSubmissionRejectsTrailingJSON pins the rule
// that a body which carries a second JSON document after the first
// MUST be rejected as malformed. Letting the trailing object
// through is a parser-confusion vector — a reverse proxy / WAF that
// reads the entire body sees a different shape than the OP
// consumed.
func TestJSONDriver_ParseSubmissionRejectsTrailingJSON(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		body string
	}{
		{name: "double-object", body: `{"state_ref":"ref-1","values":{}} {"state_ref":"ref-2","values":{}}`},
		{name: "object-then-array", body: `{"state_ref":"ref-1","values":{}}[]`},
		{name: "object-then-newline-object", body: "{\"state_ref\":\"ref-1\",\"values\":{}}\n{\"x\":1}"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := httptest.NewRequestWithContext(context.Background(), "POST", "/interaction/u-1", strings.NewReader(tc.body))
			_, err := (interaction.JSONDriver{}).ParseSubmission(r)
			if !errors.Is(err, interaction.ErrSubmissionMalformed) {
				t.Fatalf("err = %v, want ErrSubmissionMalformed", err)
			}
		})
	}
}

// drainFormBody reproduces what the interaction endpoint does to a
// form-encoded request before it hands it to the Driver: it recovers the
// CSRF token by parsing the form, which consumes r.Body. Every
// assertion about the [interaction.Driver.ParseSubmission] precondition
// has to run against a request in that state, not against a pristine
// one.
func drainFormBody(tb testing.TB, r *http.Request) {
	tb.Helper()
	if err := r.ParseForm(); err != nil {
		tb.Fatalf("ParseForm: %v", err)
	}
	if r.PostForm.Get("csrf_token") == "" {
		tb.Fatal("fixture is missing csrf_token; it does not model what the endpoint parses")
	}
}

// postFormRequest builds a form-encoded POST carrying the fields a real
// submission does.
func postFormRequest(fields url.Values) *http.Request {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/interaction/u-1",
		strings.NewReader(fields.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

// postFormDriver is a custom Driver that reads its submission the way
// the ParseSubmission contract tells an implementation to: from
// r.PostForm. It stands in for an embedder's own SSR driver, which is
// the seam the precondition exists for.
type postFormDriver struct{}

func (postFormDriver) Render(http.ResponseWriter, *http.Request, interaction.Prompt) error {
	return nil
}

func (postFormDriver) ParseSubmission(r *http.Request) (interaction.FormSubmission, error) {
	if err := r.ParseForm(); err != nil {
		return interaction.FormSubmission{}, err
	}
	values := make(map[string]string, len(r.PostForm))
	for k, vs := range r.PostForm {
		if k == "state_ref" || k == "csrf_token" {
			continue
		}
		if len(vs) > 0 {
			values[k] = vs[0]
		}
	}
	return interaction.FormSubmission{StateRef: r.PostForm.Get("state_ref"), Values: values}, nil
}

// bodyReadingDriver is the shape the contract now warns against: it
// decodes straight from r.Body without consulting r.PostForm.
type bodyReadingDriver struct{}

func (bodyReadingDriver) Render(http.ResponseWriter, *http.Request, interaction.Prompt) error {
	return nil
}

func (bodyReadingDriver) ParseSubmission(r *http.Request) (interaction.FormSubmission, error) {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return interaction.FormSubmission{}, err
	}
	parsed, err := url.ParseQuery(string(raw))
	if err != nil {
		return interaction.FormSubmission{}, err
	}
	stateRef := parsed.Get("state_ref")
	if stateRef == "" {
		return interaction.FormSubmission{}, interaction.ErrMissingStateRef
	}
	return interaction.FormSubmission{StateRef: stateRef}, nil
}

// TestDriver_FormSubmissionIsReadableFromPostForm pins the documented
// precondition on [interaction.Driver.ParseSubmission]: after the
// endpoint has parsed the form to recover the CSRF token, a Driver that
// follows the contract and reads r.PostForm still sees the whole
// submission.
func TestDriver_FormSubmissionIsReadableFromPostForm(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		driver interaction.Driver
	}{
		{name: "custom driver", driver: postFormDriver{}},
		{name: "bundled HTMLDriver", driver: interaction.HTMLDriver{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r := postFormRequest(url.Values{
				"state_ref":  {"ref-1"},
				"csrf_token": {"tok"},
				"password":   {"hunter2"},
			})
			drainFormBody(t, r)
			got, err := tc.driver.ParseSubmission(r)
			if err != nil {
				t.Fatalf("ParseSubmission: %v", err)
			}
			if got.StateRef != "ref-1" {
				t.Errorf("StateRef = %q, want ref-1", got.StateRef)
			}
			if got.Values["password"] != "hunter2" {
				t.Errorf("Values[password] = %q, want hunter2", got.Values["password"])
			}
		})
	}
}

// TestDriver_FormSubmissionIsNotReadableFromBody is the reason the
// precondition is documented rather than left implicit. A Driver that
// reads r.Body — the ordinary way to consume a request body, and what
// the method's own "MUST NOT consume more than a few KiB from r.Body"
// wording suggests — gets nothing, and turns a legitimate submission
// into a 400.
func TestDriver_FormSubmissionIsNotReadableFromBody(t *testing.T) {
	t.Parallel()

	r := postFormRequest(url.Values{
		"state_ref":  {"ref-1"},
		"csrf_token": {"tok"},
		"password":   {"hunter2"},
	})
	drainFormBody(t, r)
	if _, err := (bodyReadingDriver{}).ParseSubmission(r); !errors.Is(err, interaction.ErrMissingStateRef) {
		t.Fatalf("err = %v, want ErrMissingStateRef: the body a Driver reads directly is already drained", err)
	}
}

// TestJSONDriver_BodyIsUntouchedForNonFormSubmissions bounds the
// precondition. The endpoint only parses the form for a request that
// declares form encoding, so a JSON driver keeps reading r.Body.
func TestJSONDriver_BodyIsUntouchedForNonFormSubmissions(t *testing.T) {
	t.Parallel()

	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/interaction/u-1",
		strings.NewReader(`{"state_ref":"ref-1","values":{"password":"hunter2"}}`))
	r.Header.Set("Content-Type", "application/json")
	got, err := (interaction.JSONDriver{}).ParseSubmission(r)
	if err != nil {
		t.Fatalf("ParseSubmission: %v", err)
	}
	if got.StateRef != "ref-1" || got.Values["password"] != "hunter2" {
		t.Errorf("submission = %+v, want the JSON body decoded intact", got)
	}
}
