package authorizeendpoint_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authorizeendpoint"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// postFormDriver is a custom [interaction.Driver] that renders like
// [interaction.JSONDriver] (so the GET phase still yields the JSON
// prompt envelope the harness reads) but accepts url-encoded
// submissions. It reads the submitted fields from r.PostForm, which is
// the precondition [interaction.Driver.ParseSubmission] documents for
// form-encoded bodies, and records how many bytes were still readable
// from r.Body so a test can assert the endpoint's CSRF extraction
// really did leave the body drained rather than partially consumed.
type postFormDriver struct {
	interaction.JSONDriver

	parsed        atomic.Bool
	bodyRemainder atomic.Int64
}

// ParseSubmission implements [interaction.Driver] for url-encoded
// bodies. The values map excludes the two envelope fields (state_ref
// and csrf_token) so the orchestrator sees only the prompt's own
// inputs.
func (d *postFormDriver) ParseSubmission(r *http.Request) (interaction.FormSubmission, error) {
	rest, err := io.ReadAll(r.Body)
	if err != nil {
		return interaction.FormSubmission{}, err
	}
	d.bodyRemainder.Store(int64(len(rest)))
	d.parsed.Store(true)
	stateRef := r.PostForm.Get("state_ref")
	if stateRef == "" {
		return interaction.FormSubmission{}, errors.New("state_ref missing from the parsed form")
	}
	values := make(map[string]string, len(r.PostForm))
	for k, vs := range r.PostForm {
		if k == "state_ref" || k == "csrf_token" || len(vs) == 0 {
			continue
		}
		values[k] = vs[0]
	}
	return interaction.FormSubmission{StateRef: stateRef, Values: values}, nil
}

// postForm drives one url-encoded submission against
// /interaction/{uid} carrying the CSRF token in the body rather than
// in the X-CSRF-Token header. contentType is supplied verbatim so a
// caller can vary the media type's spelling.
func postForm(
	t *testing.T,
	h *testHarness,
	start interactionStart,
	csrfCookie *http.Cookie,
	form url.Values,
	contentType string,
) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		h.interactionPth+"/"+start.uid, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Origin", "https://op.example.com")
	req.AddCookie(start.interactionCk)
	req.AddCookie(csrfCookie)
	rr := httptest.NewRecorder()
	h.handler.ServeHTTP(rr, req)
	return rr
}

// newFormDriverHarness wires a harness whose Driver is the supplied
// form-reading driver.
func newFormDriverHarness(t *testing.T, d interaction.Driver) *testHarness {
	t.Helper()
	return newHarness(t, func(deps *authorizeendpoint.Deps) {
		deps.Driver = d
	})
}

// TestInteractionPost_CSRFFormFieldAcceptsMixedCaseContentType pins the
// media-type agreement between the endpoint's CSRF extraction and the
// Driver's own form predicate. HTTP media types are case-insensitive
// (RFC 9110 §8.3), so a submission declaring
// "Application/x-www-form-urlencoded" is a form submission every
// bundled Driver accepts; the endpoint's csrf_token extraction runs
// first and must recognise exactly the same set, or the stricter side
// answers 403 to a request the Driver would have parsed.
func TestInteractionPost_CSRFFormFieldAcceptsMixedCaseContentType(t *testing.T) {
	t.Parallel()

	driver := &postFormDriver{}
	h := newFormDriverHarness(t, driver)
	start := startInteractionFlow(t, h)

	getResp := doInteractionGet(t, h, start)
	defer getResp.Body.Close()
	stateRef, csrfCookie := readPromptStateRef(t, getResp)

	form := url.Values{
		"state_ref":              {stateRef},
		"csrf_token":             {csrfCookie.Value},
		testkit.SubjectFieldName: {"user-1"},
	}
	rr := postForm(t, h, start, csrfCookie, form, "Application/x-www-form-urlencoded")

	if rr.Code == http.StatusForbidden {
		t.Fatalf("mixed-case form submission rejected by the CSRF gate: body=%s", rr.Body.String())
	}
	if rr.Code != http.StatusFound {
		t.Fatalf("status=%d want 302 body=%s", rr.Code, rr.Body.String())
	}
	if loc := rr.Header().Get("Location"); !strings.Contains(loc, "code=") {
		t.Errorf("Location=%q must carry code", loc)
	}
	if !driver.parsed.Load() {
		t.Error("ParseSubmission was never reached")
	}
}

// TestInteractionPost_FormDriverReadsParsedForm drives a custom Driver
// that accepts url-encoded submissions across the same request the
// endpoint took the CSRF token out of. The endpoint parses the body to
// recover the csrf_token field, so by the time ParseSubmission runs
// r.Body is drained; the documented contract is that such a Driver
// reads its fields from r.PostForm. The row asserts both halves: the
// submission succeeds (the redirect carries a code) and the Driver
// observed an empty r.Body, which is what makes the r.PostForm
// requirement in the contract load-bearing rather than advisory.
func TestInteractionPost_FormDriverReadsParsedForm(t *testing.T) {
	t.Parallel()

	driver := &postFormDriver{}
	h := newFormDriverHarness(t, driver)
	start := startInteractionFlow(t, h)

	getResp := doInteractionGet(t, h, start)
	defer getResp.Body.Close()
	stateRef, csrfCookie := readPromptStateRef(t, getResp)

	form := url.Values{
		"state_ref":              {stateRef},
		"csrf_token":             {csrfCookie.Value},
		testkit.SubjectFieldName: {"user-1"},
	}
	rr := postForm(t, h, start, csrfCookie, form, "application/x-www-form-urlencoded")

	if rr.Code != http.StatusFound {
		t.Fatalf("status=%d want 302 body=%s", rr.Code, rr.Body.String())
	}
	if loc := rr.Header().Get("Location"); !strings.Contains(loc, "code=") {
		t.Errorf("Location=%q must carry code", loc)
	}
	if !driver.parsed.Load() {
		t.Fatal("ParseSubmission was never reached")
	}
	if got := driver.bodyRemainder.Load(); got != 0 {
		t.Errorf("r.Body still held %d bytes at ParseSubmission; the documented precondition is a drained body", got)
	}
}
