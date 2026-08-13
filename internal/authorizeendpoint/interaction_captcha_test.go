package authorizeendpoint_test

// End-to-end coverage for the after-N-failures captcha gate.
//
// The gate is only usable if the token the SPA collects actually
// reaches the verifier, which requires three things to line up: the
// prompt has to advertise the field, the driver has to render (or
// echo) it, and the orchestrator has to read it back off the
// submission. These tests drive the whole loop over HTTP for both
// shipped drivers so a regression in any one of the three surfaces as a
// login that cannot complete rather than as a passing unit test.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/internal/authorizeendpoint"
	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
)

// captchaGoodToken is the only token the test verifier accepts.
const captchaGoodToken = "provider-token-ok"

// captchaBadSubject is the credential the test factor rejects with a
// soft retry, so a test can walk the failure counter up to the gate.
const captchaBadSubject = "wrong-user"

// retrySubjectPromptType is the prompt [retryingSubjectAuthenticator]
// emits. The testkit namespace marks it as test-only.
const retrySubjectPromptType = "auth.testkit.retry-subject"

// retrySubjectField is the credential field the test factor reads.
const retrySubjectField = "subject"

// retryingSubjectAuthenticator binds whatever subject the submission
// carries, except for [captchaBadSubject], which it rejects as a soft
// credential failure. It stands in for a password factor: the
// orchestrator advances the brute-force counter on every rejection,
// which is what eventually interposes the captcha challenge.
type retryingSubjectAuthenticator struct{}

func (retryingSubjectAuthenticator) Type() op.FactorType { return "testkit.retry-subject" }
func (retryingSubjectAuthenticator) AAL() op.AAL         { return op.AAL1 }
func (retryingSubjectAuthenticator) AMR() string         { return "" }
func (retryingSubjectAuthenticator) Prompts() []string   { return []string{retrySubjectPromptType} }

func (retryingSubjectAuthenticator) Begin(_ context.Context, _ op.BeginInput) (interaction.Step, error) {
	return interaction.Step{Prompt: &interaction.Prompt{
		Type: retrySubjectPromptType,
		Inputs: []interaction.FieldSpec{{
			Name:     retrySubjectField,
			Kind:     interaction.FieldText,
			Required: true,
			MinLen:   1,
			MaxLen:   256,
		}},
	}}, nil
}

func (retryingSubjectAuthenticator) Continue(_ context.Context, in op.ContinueInput) (interaction.Step, error) {
	sub := in.Submission.Values[retrySubjectField]
	if sub == "" || sub == captchaBadSubject {
		return interaction.Step{}, authn.ErrFactorRetry
	}
	return interaction.Step{Result: &interaction.Result{Subject: sub, AuthTime: in.AuthTime}}, nil
}

var _ op.Authenticator = retryingSubjectAuthenticator{}

// countingCaptchaVerifier accepts [captchaGoodToken] and rejects every
// other value, recording each token it was handed so a test can assert
// the orchestrator forwarded what the driver submitted.
type countingCaptchaVerifier struct {
	mu     sync.Mutex
	tokens []string
}

func (c *countingCaptchaVerifier) Verify(_ context.Context, in op.CaptchaInput) error {
	c.mu.Lock()
	c.tokens = append(c.tokens, in.Token)
	c.mu.Unlock()
	if in.Token != captchaGoodToken {
		return errCaptchaRejected
	}
	return nil
}

func (c *countingCaptchaVerifier) seen() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.tokens...)
}

// errCaptchaRejected is the fixed rejection the test verifier returns.
// The orchestrator never surfaces the reason to the SPA.
var errCaptchaRejected = errors.New("captcha token rejected")

// captchaThreshold mirrors the orchestrator's unexported credential
// failure count that interposes the challenge. It is duplicated rather
// than exported because the number is an internal tuning knob, not a
// contract; if the two drift the tests below fail loudly on the prompt
// type rather than silently stopping short of the gate.
const captchaThreshold = 3

// buildCaptchaOrchestrator wires the chain the captcha tests drive: one
// soft-failing credential factor plus the counting verifier.
func buildCaptchaOrchestrator(t *testing.T, verifier op.CaptchaVerifier) *authn.Orchestrator {
	t.Helper()
	signer, err := authn.NewStateRefSigner(bytes.Repeat([]byte{0x5A}, 32))
	if err != nil {
		t.Fatalf("NewStateRefSigner: %v", err)
	}
	orch, err := authn.New(authn.Config{
		Authenticators: []op.Authenticator{retryingSubjectAuthenticator{}},
		Captcha:        verifier,
		StateRefSigner: signer,
	})
	if err != nil {
		t.Fatalf("authn.New: %v", err)
	}
	return orch
}

// promptEnvelope is the subset of the JSON prompt envelope the captcha
// tests assert on.
type promptEnvelope struct {
	Type     string `json:"type"`
	StateRef string `json:"state_ref"`
	Inputs   []struct {
		Name string
	} `json:"inputs"`
}

func (p promptEnvelope) hasInput(name string) bool {
	for _, in := range p.Inputs {
		if in.Name == name {
			return true
		}
	}
	return false
}

// interactionGET runs GET /interaction/{uid} and returns the raw
// recorder so the caller can decode either envelope shape.
func interactionGET(t *testing.T, h *testHarness, start interactionStart) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		h.interactionPth+"/"+start.uid, http.NoBody)
	req.AddCookie(start.interactionCk)
	rr := httptest.NewRecorder()
	h.handler.ServeHTTP(rr, req)
	return rr
}

// decodeJSONPrompt reads the SPA envelope plus the CSRF cookie the
// response set. Every prompt re-issues the cookie, so the caller must
// carry the freshest one into the next POST.
func decodeJSONPrompt(t *testing.T, rr *httptest.ResponseRecorder) (promptEnvelope, *http.Cookie) {
	t.Helper()
	if rr.Code != http.StatusOK {
		t.Fatalf("prompt status=%d body=%s", rr.Code, rr.Body.String())
	}
	var env promptEnvelope
	if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode prompt: %v body=%s", err, rr.Body.String())
	}
	if env.StateRef == "" {
		t.Fatalf("prompt carries no state_ref: %s", rr.Body.String())
	}
	return env, requireCSRFCookie(t, rr)
}

// requireCSRFCookie pulls the __Host-oidc_csrf cookie off a response.
func requireCSRFCookie(t *testing.T, rr *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rr.Result().Cookies() {
		if c.Name == cookie.CSRFProfile.Name {
			return c
		}
	}
	t.Fatal("csrf cookie missing")
	return nil
}

// persistedAuthnState reads the chain state the endpoint saved for uid.
// The captcha tests use it to assert the failure counter advanced —
// the counter lives in the interaction record, not on the wire.
func persistedAuthnState(t *testing.T, h *testHarness, uid string) authn.State {
	t.Helper()
	rec, err := h.store.Interactions().Find(context.Background(), uid)
	if err != nil {
		t.Fatalf("Find interaction: %v", err)
	}
	state, err := authorize.UnmarshalState(rec.RawState)
	if err != nil {
		t.Fatalf("UnmarshalState: %v", err)
	}
	var st authn.State
	if err := json.Unmarshal(state.Authn, &st); err != nil {
		t.Fatalf("decode authn state: %v", err)
	}
	return st
}

// TestInteractionCaptcha_SPAEnvelopeCompletesLogin drives the whole
// gate through the JSON driver: fail the credential factor until the
// threshold trips, clear the interposed challenge with a token posted
// under the advertised field, then complete the login.
//
// Before the token was wired the second half of this flow was
// unreachable: the challenge re-emitted forever because the verifier
// was always handed an empty token, so a deployment with a captcha
// verifier configured locked out every user who mistyped a password
// often enough.
func TestInteractionCaptcha_SPAEnvelopeCompletesLogin(t *testing.T) {
	t.Parallel()

	verifier := &countingCaptchaVerifier{}
	h := newHarness(t, func(d *authorizeendpoint.Deps) {
		d.Authn = buildCaptchaOrchestrator(t, verifier)
	})
	start := startInteractionFlow(t, h)

	prompt, csrfCookie := decodeJSONPrompt(t, interactionGET(t, h, start))
	if prompt.Type != retrySubjectPromptType {
		t.Fatalf("first prompt = %q, want %q", prompt.Type, retrySubjectPromptType)
	}

	// Walk the brute-force counter up to, but not past, the threshold.
	// Each of these failures re-emits the credential prompt.
	for i := range captchaThreshold - 1 {
		rr := postSubmission(t, h, start, csrfCookie, interaction.FormSubmission{
			StateRef: prompt.StateRef,
			Values:   map[string]string{retrySubjectField: captchaBadSubject},
		})
		prompt, csrfCookie = decodeJSONPrompt(t, rr)
		if prompt.Type != retrySubjectPromptType {
			t.Fatalf("retry %d prompt = %q, want the credential prompt", i, prompt.Type)
		}
	}

	// The failure that crosses the threshold interposes the challenge on
	// the spot. Answering the submission with the credential prompt again
	// would make the gate reachable only by re-entering the dispatcher,
	// which a submit-only guessing loop never does: the browser would
	// have to reload the interaction for the challenge to appear at all.
	rr := postSubmission(t, h, start, csrfCookie, interaction.FormSubmission{
		StateRef: prompt.StateRef,
		Values:   map[string]string{retrySubjectField: captchaBadSubject},
	})
	prompt, csrfCookie = decodeJSONPrompt(t, rr)
	if prompt.Type != "captcha" {
		t.Fatalf("prompt on the failure that crosses the threshold = %q, want captcha", prompt.Type)
	}
	if !prompt.hasInput(authn.CaptchaTokenField) {
		t.Fatalf("captcha envelope advertises inputs %+v, want a %q field",
			prompt.Inputs, authn.CaptchaTokenField)
	}

	// A rejected token re-emits the challenge and advances the captcha
	// failure counter.
	rr = postSubmission(t, h, start, csrfCookie, interaction.FormSubmission{
		StateRef: prompt.StateRef,
		Values:   map[string]string{authn.CaptchaTokenField: "not-the-token"},
	})
	prompt, csrfCookie = decodeJSONPrompt(t, rr)
	if prompt.Type != "captcha" {
		t.Fatalf("prompt after a rejected token = %q, want captcha", prompt.Type)
	}
	if got := persistedAuthnState(t, h, start.uid); got.CaptchaFailures != 1 {
		t.Errorf("persisted CaptchaFailures = %d, want 1", got.CaptchaFailures)
	}

	// The real token clears the gate and the chain returns to the factor.
	rr = postSubmission(t, h, start, csrfCookie, interaction.FormSubmission{
		StateRef: prompt.StateRef,
		Values:   map[string]string{authn.CaptchaTokenField: captchaGoodToken},
	})
	prompt, csrfCookie = decodeJSONPrompt(t, rr)
	if prompt.Type != retrySubjectPromptType {
		t.Fatalf("prompt after clearing the captcha = %q, want the credential prompt", prompt.Type)
	}
	if got := persistedAuthnState(t, h, start.uid); !got.CaptchaPassed {
		t.Error("persisted CaptchaPassed = false after a valid token")
	}

	// And the good credential now completes the login.
	final := postSubmission(t, h, start, csrfCookie, interaction.FormSubmission{
		StateRef: prompt.StateRef,
		Values:   map[string]string{retrySubjectField: "user-1"},
	})
	if final.Code != http.StatusFound {
		t.Fatalf("final status=%d body=%s", final.Code, final.Body.String())
	}
	if loc := final.Header().Get("Location"); !strings.Contains(loc, "code=") {
		t.Errorf("Location=%q must carry an authorization code", loc)
	}

	if got := verifier.seen(); len(got) != 2 || got[0] != "not-the-token" || got[1] != captchaGoodToken {
		t.Errorf("verifier saw tokens %q, want [not-the-token %s]", got, captchaGoodToken)
	}
}

// hiddenFieldValue extracts the value of a hidden input the HTML
// driver rendered.
func hiddenFieldValue(t *testing.T, body, name string) string {
	t.Helper()
	re := regexp.MustCompile(`<input type="hidden" name="` + regexp.QuoteMeta(name) + `" value="([^"]*)">`)
	m := re.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("hidden field %q not rendered in:\n%s", name, body)
	}
	return m[1]
}

// postHTMLForm posts a url-encoded submission the way a browser would,
// carrying the CSRF token in the form body rather than a header.
func postHTMLForm(
	t *testing.T,
	h *testHarness,
	start interactionStart,
	csrfCookie *http.Cookie,
	values url.Values,
) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		h.interactionPth+"/"+start.uid, strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://op.example.com")
	req.AddCookie(start.interactionCk)
	req.AddCookie(csrfCookie)
	rr := httptest.NewRecorder()
	h.handler.ServeHTTP(rr, req)
	return rr
}

// htmlPrompt bundles the hidden fields the next HTML submission needs.
type htmlPrompt struct {
	body      string
	stateRef  string
	csrfToken string
	cookie    *http.Cookie
}

func readHTMLPrompt(t *testing.T, rr *httptest.ResponseRecorder) htmlPrompt {
	t.Helper()
	if rr.Code != http.StatusOK {
		t.Fatalf("prompt status=%d body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	return htmlPrompt{
		body:      body,
		stateRef:  hiddenFieldValue(t, body, "state_ref"),
		csrfToken: hiddenFieldValue(t, body, "csrf_token"),
		cookie:    requireCSRFCookie(t, rr),
	}
}

// TestInteractionCaptcha_HTMLDriverCompletesLogin is the server-rendered
// companion to the SPA flow. The built-in HTML driver renders the
// prompt's [interaction.FieldSpec] list verbatim, so the captcha token
// only has somewhere to live in the form if the prompt declares it — a
// page without the field leaves a no-JS deployment permanently stuck at
// the challenge.
func TestInteractionCaptcha_HTMLDriverCompletesLogin(t *testing.T) {
	t.Parallel()

	verifier := &countingCaptchaVerifier{}
	h := newHarness(t, func(d *authorizeendpoint.Deps) {
		d.Authn = buildCaptchaOrchestrator(t, verifier)
		d.Driver = interaction.HTMLDriver{}
	})
	start := startInteractionFlow(t, h)

	page := readHTMLPrompt(t, interactionGET(t, h, start))

	for range 3 {
		rr := postHTMLForm(t, h, start, page.cookie, url.Values{
			"state_ref":       {page.stateRef},
			"csrf_token":      {page.csrfToken},
			retrySubjectField: {captchaBadSubject},
		})
		page = readHTMLPrompt(t, rr)
	}

	page = readHTMLPrompt(t, interactionGET(t, h, start))
	if !strings.Contains(page.body, `name="`+authn.CaptchaTokenField+`"`) {
		t.Fatalf("captcha page does not render the %q field:\n%s", authn.CaptchaTokenField, page.body)
	}

	// A rejected token keeps the user on the challenge and advances the
	// captcha failure counter.
	rr := postHTMLForm(t, h, start, page.cookie, url.Values{
		"state_ref":             {page.stateRef},
		"csrf_token":            {page.csrfToken},
		authn.CaptchaTokenField: {"not-the-token"},
	})
	page = readHTMLPrompt(t, rr)
	if !strings.Contains(page.body, `name="`+authn.CaptchaTokenField+`"`) {
		t.Fatalf("rejected token did not re-render the challenge:\n%s", page.body)
	}
	if got := persistedAuthnState(t, h, start.uid); got.CaptchaFailures != 1 {
		t.Errorf("persisted CaptchaFailures = %d, want 1", got.CaptchaFailures)
	}

	// The real token clears the gate and returns the browser to the
	// credential form.
	rr = postHTMLForm(t, h, start, page.cookie, url.Values{
		"state_ref":             {page.stateRef},
		"csrf_token":            {page.csrfToken},
		authn.CaptchaTokenField: {captchaGoodToken},
	})
	page = readHTMLPrompt(t, rr)
	if !strings.Contains(page.body, `name="`+retrySubjectField+`"`) {
		t.Fatalf("cleared captcha did not return to the credential form:\n%s", page.body)
	}

	final := postHTMLForm(t, h, start, page.cookie, url.Values{
		"state_ref":       {page.stateRef},
		"csrf_token":      {page.csrfToken},
		retrySubjectField: {"user-1"},
	})
	if final.Code != http.StatusFound {
		t.Fatalf("final status=%d body=%s", final.Code, final.Body.String())
	}
	if loc := final.Header().Get("Location"); !strings.Contains(loc, "code=") {
		t.Errorf("Location=%q must carry an authorization code", loc)
	}

	if got := verifier.seen(); len(got) != 2 || got[0] != "not-the-token" || got[1] != captchaGoodToken {
		t.Errorf("verifier saw tokens %q, want [not-the-token %s]", got, captchaGoodToken)
	}
}

// fillableInputs returns the names of the inputs the rendered page lets
// a user type into. Hidden inputs are excluded: their value is fixed by
// the markup and no browser will change it without script, which this
// surface does not serve.
func fillableInputs(body string) map[string]struct{} {
	re := regexp.MustCompile(`<input name="([^"]*)" type="([^"]*)"`)
	out := map[string]struct{}{}
	for _, m := range re.FindAllStringSubmatch(body, -1) {
		if m[2] == "hidden" {
			continue
		}
		out[m[1]] = struct{}{}
	}
	return out
}

// browserSubmission builds the POST body a browser would produce from
// the rendered page: every hidden input at exactly the value the server
// wrote into it, plus what the user typed into the fields the page
// actually offered. Asking for a field the page did not offer fails the
// test, because a browser has no way to invent one.
func browserSubmission(t *testing.T, body string, typed map[string]string) url.Values {
	t.Helper()
	values := url.Values{}
	hidden := regexp.MustCompile(`<input type="hidden" name="([^"]*)" value="([^"]*)">`)
	for _, m := range hidden.FindAllStringSubmatch(body, -1) {
		values.Set(m[1], m[2])
	}
	offered := fillableInputs(body)
	for name, value := range typed {
		if _, ok := offered[name]; !ok {
			t.Fatalf("the page offers no fillable %q input, so a browser cannot submit one:\n%s", name, body)
		}
		values.Set(name, value)
	}
	return values
}

// TestInteractionCaptcha_HTMLDriverChallengeIsAnswerableByABrowser is
// the no-script version of the captcha gate, driven the way a browser
// would drive it: nothing is posted that the rendered page did not
// offer.
//
// The distinction matters because the orchestrator spends an attempt on
// every rejected token and abandons the chain once they run out. A
// challenge page whose token field cannot receive a value is therefore
// not a cosmetic gap — it is a lockout for every user who reaches the
// gate, and one that a test synthesising its own POST body would never
// notice.
func TestInteractionCaptcha_HTMLDriverChallengeIsAnswerableByABrowser(t *testing.T) {
	t.Parallel()

	verifier := &countingCaptchaVerifier{}
	h := newHarness(t, func(d *authorizeendpoint.Deps) {
		d.Authn = buildCaptchaOrchestrator(t, verifier)
		d.Driver = interaction.HTMLDriver{}
	})
	start := startInteractionFlow(t, h)

	page := readHTMLPrompt(t, interactionGET(t, h, start))
	for range captchaThreshold {
		rr := postHTMLForm(t, h, start, page.cookie,
			browserSubmission(t, page.body, map[string]string{retrySubjectField: captchaBadSubject}))
		page = readHTMLPrompt(t, rr)
	}

	page = readHTMLPrompt(t, interactionGET(t, h, start))
	if _, ok := fillableInputs(page.body)[authn.CaptchaTokenField]; !ok {
		t.Fatalf("challenge page offers no fillable %q input; every user who reaches the gate is stuck:\n%s",
			authn.CaptchaTokenField, page.body)
	}

	// The user types the token and the chain leaves the challenge.
	rr := postHTMLForm(t, h, start, page.cookie,
		browserSubmission(t, page.body, map[string]string{authn.CaptchaTokenField: captchaGoodToken}))
	page = readHTMLPrompt(t, rr)
	if _, ok := fillableInputs(page.body)[retrySubjectField]; !ok {
		t.Fatalf("cleared captcha did not return to the credential form:\n%s", page.body)
	}

	final := postHTMLForm(t, h, start, page.cookie,
		browserSubmission(t, page.body, map[string]string{retrySubjectField: "user-1"}))
	if final.Code != http.StatusFound {
		t.Fatalf("final status=%d body=%s", final.Code, final.Body.String())
	}
	if loc := final.Header().Get("Location"); !strings.Contains(loc, "code=") {
		t.Errorf("Location=%q must carry an authorization code", loc)
	}
	if got := verifier.seen(); len(got) != 1 || got[0] != captchaGoodToken {
		t.Errorf("verifier saw tokens %q, want exactly the token the user typed", got)
	}
}
