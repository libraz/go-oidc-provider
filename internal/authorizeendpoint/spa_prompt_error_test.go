package authorizeendpoint_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authn"
	"github.com/libraz/go-oidc-provider/internal/authorizeendpoint"
	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/i18n"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
)

const (
	promptErrorSecret     = "right-password"
	promptErrorPromptType = "auth.testkit.password"
)

// passwordStub is a first factor that accepts one fixed password and
// reports every other submission as a retryable rejection.
type passwordStub struct{ typ op.FactorType }

func (s passwordStub) Type() op.FactorType { return s.typ }
func (passwordStub) AAL() op.AAL           { return op.AAL1 }
func (passwordStub) AMR() string           { return "" }
func (passwordStub) Prompts() []string     { return []string{promptErrorPromptType} }

func (passwordStub) Begin(context.Context, op.BeginInput) (interaction.Step, error) {
	return interaction.Step{Prompt: &interaction.Prompt{
		Type: promptErrorPromptType,
		Inputs: []interaction.FieldSpec{{
			Name:     "password",
			Kind:     interaction.FieldPassword,
			Label:    "auth.password.password",
			Required: true,
			MinLen:   1,
			MaxLen:   256,
		}},
	}}, nil
}

func (passwordStub) Continue(_ context.Context, in op.ContinueInput) (interaction.Step, error) {
	if in.Submission.Values["password"] != promptErrorSecret {
		return interaction.Step{}, fmt.Errorf("passwordStub: wrong password: %w", authn.ErrFactorRetry)
	}
	return interaction.Step{Result: &interaction.Result{Subject: "user-1", AuthTime: in.AuthTime}}, nil
}

// newPromptErrorHarness builds the SPA state routes over a login flow that
// is either a single password step or, with chooser set, a one-of between
// two factors. withResolver wires the embedded i18n bundles.
func newPromptErrorHarness(t *testing.T, chooser, withResolver bool) *spaHarness {
	t.Helper()

	step := authn.LoginFlowStep{Kind: "password", Authenticator: passwordStub{typ: op.FactorPassword}}
	if chooser {
		step = authn.LoginFlowStep{
			Kind: "one_of(myorg.ldap,password)",
			OneOf: []authn.LoginFlowStep{
				{Kind: "password", Authenticator: passwordStub{typ: op.FactorPassword}},
				{Kind: "myorg.ldap", Authenticator: passwordStub{typ: "myorg.ldap"}},
			},
			IfNoneEnrolled: authn.UnenrolledDeny,
		}
	}
	flow, err := authn.CompileLoginFlow(authn.LoginFlowSpec{Primary: step})
	if err != nil {
		t.Fatalf("CompileLoginFlow: %v", err)
	}
	signer, err := authn.NewStateRefSigner(bytes.Repeat([]byte{0xCD}, 32))
	if err != nil {
		t.Fatalf("NewStateRefSigner: %v", err)
	}
	orch, err := authn.New(authn.Config{LoginFlow: flow, StateRefSigner: signer})
	if err != nil {
		t.Fatalf("authn.New: %v", err)
	}

	var resolver *i18n.Resolver
	if withResolver {
		bundles, err := i18n.DefaultBundles()
		if err != nil {
			t.Fatalf("DefaultBundles: %v", err)
		}
		resolver, err = i18n.NewResolver(i18n.English, bundles...)
		if err != nil {
			t.Fatalf("NewResolver: %v", err)
		}
	}

	staticDir := t.TempDir()
	mustWriteFile(t, filepath.Join(staticDir, "index.html"), "<!doctype html><html><body>SHELL</body></html>")
	base := newHarness(t, func(d *authorizeendpoint.Deps) {
		d.Authn = orch
		d.SPALoginMount = "/login"
		d.SPAStaticDir = staticDir
		d.LocaleResolver = resolver
	})
	return &spaHarness{testHarness: base, loginMount: "/login", staticDir: staticDir}
}

// stateClient walks one interaction's SPA state route the way a SPA does,
// carrying the interaction cookie and the latest CSRF cookie between hops.
type stateClient struct {
	t      *testing.T
	h      *spaHarness
	url    string
	icook  *http.Cookie
	csrf   *http.Cookie
	locale string
}

func newStateClient(t *testing.T, h *spaHarness, locale string) *stateClient {
	t.Helper()
	uid, cookieVal := primeInteraction(t, h)
	return &stateClient{
		t:      t,
		h:      h,
		url:    h.loginMount + "/state/" + uid,
		icook:  &http.Cookie{Name: cookie.InteractionProfile.Name, Value: cookieVal},
		locale: locale,
	}
}

func (c *stateClient) do(req *http.Request) (int, map[string]any) {
	c.t.Helper()
	req.AddCookie(c.icook)
	if c.csrf != nil {
		req.AddCookie(c.csrf)
	}
	if c.locale != "" {
		req.Header.Set("Accept-Language", c.locale)
	}
	w := httptest.NewRecorder()
	c.h.handler.ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()
	if ck := findCookie(resp.Cookies(), cookie.CSRFProfile.Name); ck != nil {
		c.csrf = ck
	}
	return resp.StatusCode, decodeMap(c.t, resp)
}

func (c *stateClient) get() map[string]any {
	c.t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, c.url, http.NoBody)
	status, body := c.do(req)
	if status != http.StatusOK {
		c.t.Fatalf("GET state status=%d body=%v", status, body)
	}
	return body
}

func (c *stateClient) post(stateRef, password string) map[string]any {
	c.t.Helper()
	raw, err := json.Marshal(interaction.FormSubmission{
		StateRef: stateRef,
		Values:   map[string]string{"password": password},
	})
	if err != nil {
		c.t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, c.url, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", "https://op.example.com")
	req.Header.Set("X-CSRF-Token", c.csrf.Value)
	status, body := c.do(req)
	if status != http.StatusOK {
		c.t.Fatalf("POST state status=%d body=%v", status, body)
	}
	return body
}

func promptErrorOf(t *testing.T, body map[string]any) (perr map[string]any, ok bool) {
	t.Helper()
	raw, present := body["error"]
	if !present {
		return nil, false
	}
	perr, isMap := raw.(map[string]any)
	if !isMap {
		t.Fatalf("error member is %T, want an object: %v", raw, body)
	}
	return perr, true
}

func inputLabelText(t *testing.T, body map[string]any) (string, bool) {
	t.Helper()
	inputs, _ := body["inputs"].([]any)
	if len(inputs) == 0 {
		t.Fatalf("prompt carries no inputs: %v", body)
	}
	first, _ := inputs[0].(map[string]any)
	text, ok := first["label_text"].(string)
	return text, ok
}

func TestSPAStatePost_WrongPassword_CarriesPromptError(t *testing.T) {
	t.Parallel()

	h := newPromptErrorHarness(t, false, true)
	c := newStateClient(t, h, "en")

	first := c.get()
	if _, has := promptErrorOf(t, first); has {
		t.Fatalf("the first prompt must carry no error: %v", first)
	}

	rejected := c.post(first["state_ref"].(string), "wrong-password")
	perr, has := promptErrorOf(t, rejected)
	if !has {
		t.Fatalf("a rejected password must carry error: %v", rejected)
	}
	if perr["code"] != interaction.PromptErrorCredentialsRejected {
		t.Errorf("error.code = %v, want %q", perr["code"], interaction.PromptErrorCredentialsRejected)
	}
	if perr["message"] != "The details you entered are incorrect. Try again." {
		t.Errorf("error.message = %v, want the resolved English text", perr["message"])
	}

	// A GET re-runs the tick, so the notice does not outlive the response
	// that carried it.
	again := c.get()
	if _, has := promptErrorOf(t, again); has {
		t.Errorf("a fresh GET must not repeat the error: %v", again)
	}

	next := c.post(again["state_ref"].(string), promptErrorSecret)
	if _, has := promptErrorOf(t, next); has {
		t.Errorf("the transition after a correct password must carry no error: %v", next)
	}
}

func TestSPAStateGet_LabelTextResolvedPerLocale(t *testing.T) {
	t.Parallel()

	t.Run("input label", func(t *testing.T) {
		t.Parallel()
		for locale, want := range map[string]string{"en": "Password", "ja": "パスワード"} {
			h := newPromptErrorHarness(t, false, true)
			body := newStateClient(t, h, locale).get()
			got, ok := inputLabelText(t, body)
			if !ok || got != want {
				t.Errorf("locale %s: inputs[0].label_text = %q (present=%v), want %q", locale, got, ok, want)
			}
			if body["locale"] != locale {
				t.Errorf("locale %s: prompt.locale = %v", locale, body["locale"])
			}
		}
	})

	t.Run("factor option label", func(t *testing.T) {
		t.Parallel()
		for locale, want := range map[string]string{"en": "Password", "ja": "パスワード"} {
			h := newPromptErrorHarness(t, true, true)
			body := newStateClient(t, h, locale).get()
			data, _ := body["data"].(map[string]any)
			options, _ := data["options"].([]any)
			if len(options) != 2 {
				t.Fatalf("locale %s: options = %v, want 2", locale, data)
			}
			for _, raw := range options {
				opt, _ := raw.(map[string]any)
				switch opt["kind"] {
				case "password":
					if opt["label_text"] != want {
						t.Errorf("locale %s: password option label_text = %v, want %q", locale, opt["label_text"], want)
					}
				case "myorg.ldap":
					// No catalogue entry: the text stays absent and the key
					// is all a renderer has.
					if _, has := opt["label_text"]; has {
						t.Errorf("locale %s: uncatalogued option carries label_text: %v", locale, opt)
					}
				default:
					t.Errorf("locale %s: unexpected option %v", locale, opt)
				}
			}
		}
	})
}

func TestSPAStatePost_NoResolver_CodeOnly(t *testing.T) {
	t.Parallel()

	h := newPromptErrorHarness(t, false, false)
	c := newStateClient(t, h, "ja")

	first := c.get()
	if text, has := inputLabelText(t, first); has {
		t.Errorf("no resolver: label_text = %q, want it absent", text)
	}

	rejected := c.post(first["state_ref"].(string), "wrong-password")
	perr, has := promptErrorOf(t, rejected)
	if !has {
		t.Fatalf("a rejected password must carry error even without a resolver: %v", rejected)
	}
	if perr["code"] != interaction.PromptErrorCredentialsRejected {
		t.Errorf("error.code = %v, want %q", perr["code"], interaction.PromptErrorCredentialsRejected)
	}
	if _, has := perr["message"]; has {
		t.Errorf("no resolver: error.message = %v, want it absent", perr["message"])
	}
	if text, has := inputLabelText(t, rejected); has {
		t.Errorf("no resolver: label_text = %q after rejection, want it absent", text)
	}
}
