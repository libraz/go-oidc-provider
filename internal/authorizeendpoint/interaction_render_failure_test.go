package authorizeendpoint_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/authn/consent"
	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// errConsentTemplateBroken is what the fixture Driver below returns
// instead of rendering. It models the failure an embedder's template
// actually produces — a nil dereference or a missing field inside
// [template.Template.Execute] — which surfaces to the endpoint as a
// Render error and nothing else.
var errConsentTemplateBroken = errors.New("consent template execution failed")

// brokenConsentDriver renders every prompt through the built-in HTML
// driver except the consent screen, where it fails without touching the
// response writer. Failing only the consent prompt is what lets the test
// reach the branch through a real ceremony: the authn step still renders,
// so the chain advances to a prompt the Driver cannot produce, exactly as
// a deployment with one broken template would.
type brokenConsentDriver struct {
	interaction.HTMLDriver
}

func (d brokenConsentDriver) Render(w http.ResponseWriter, r *http.Request, prompt interaction.Prompt) error {
	if prompt.Type == consent.PromptType {
		return errConsentTemplateBroken
	}
	return d.HTMLDriver.Render(w, r, prompt)
}

// TestEndToEnd_InteractionRenderFailureIsNotAnEmptyOK pins the response
// to a Driver that fails before committing anything.
//
// net/http answers a handler that returns having written nothing with an
// implicit 200 OK and an empty body, so a template fault used to reach
// the user as a blank page the browser was told had rendered
// successfully — indistinguishable from a prompt with no fields, and
// invisible to any monitor watching status codes. The endpoint has to
// answer the failure itself.
func TestEndToEnd_InteractionRenderFailureIsNotAnEmptyOK(t *testing.T) {
	t.Parallel()

	clock := fakeClock{now: time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)}
	sink := &auditSink{}
	tk := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(
			op.WithInteractionDriver(brokenConsentDriver{}),
			op.WithAuditLogger(slog.New(slog.NewJSONHandler(sink, nil))),
		),
	)

	const secret = "rp-secret"
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      "rp-render-failure",
		SecretHash:              hash,
		RedirectURIs:            []string{"https://rp.testkit.invalid/callback"},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	client := tk.HTTPClient(jar)
	ctx := context.Background()

	authResp, err := newGet(tk.Server.URL + "/oidc/auth?" + e2eAuthorizeValues(rp.ID, rp.RedirectURIs[0]).Encode()).
		Do(client)
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer authResp.Body.Close()
	if authResp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status=%d, want 302", authResp.StatusCode)
	}
	location, err := authResp.Location()
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	interactionURL := tk.Server.URL + location.Path
	interactionCookie := findCookie(authResp.Cookies(), cookie.InteractionProfile.Name)
	if interactionCookie == nil {
		t.Fatal("__Host-oidc_interaction cookie missing on authorize 302")
	}

	// The authn prompt renders normally, which is the control: reaching
	// the consent step at all proves the 5xx below comes from the render
	// failure and not from a chain that never started.
	stepResp, err := doGetWithCookies(ctx, client, interactionURL, interactionCookie)
	if err != nil {
		t.Fatalf("GET interaction: %v", err)
	}
	defer stepResp.Body.Close()
	if stepResp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(stepResp.Body)
		t.Fatalf("interaction GET status=%d body=%s", stepResp.StatusCode, string(dump))
	}
	authBody, err := io.ReadAll(stepResp.Body)
	if err != nil {
		t.Fatalf("read auth body: %v", err)
	}
	authStateRef := extractStateRef(t, string(authBody))
	authCSRF := findCookie(stepResp.Cookies(), cookie.CSRFProfile.Name)
	if authCSRF == nil {
		t.Fatal("csrf cookie missing on the authn prompt")
	}

	// Submitting the subject advances the chain to the consent prompt,
	// which is the one the Driver refuses to render.
	form := url.Values{
		"state_ref":  {authStateRef},
		"csrf_token": {authCSRF.Value},
		"subject":    {"user-render-failure"},
	}
	failResp, err := doFormPost(ctx, client, interactionURL, tk.Issuer, form, interactionCookie, authCSRF)
	if err != nil {
		t.Fatalf("POST auth step: %v", err)
	}
	defer failResp.Body.Close()
	body, err := io.ReadAll(failResp.Body)
	if err != nil {
		t.Fatalf("read failure body: %v", err)
	}
	if failResp.StatusCode < 500 || failResp.StatusCode > 599 {
		t.Fatalf("status=%d body=%q, want a 5xx: a Driver that rendered nothing must not be reported as success",
			failResp.StatusCode, string(body))
	}
	if len(body) == 0 {
		t.Error("body is empty; the user is shown a blank page with no indication the prompt failed")
	}
	if !strings.Contains(string(body), errServerErrorCode) {
		t.Errorf("body=%q, want it to carry the %q wire code", string(body), errServerErrorCode)
	}

	// The wire response is deliberately generic, so the audit record is
	// the only place the cause survives. Without it an operator sees a
	// 500 rate with no way to tell which prompt stopped rendering.
	failures := auditExtrasFor(t, sink.String(), string(op.AuditInteractionRenderFailed))
	if len(failures) != 1 {
		t.Fatalf("%s emitted %d times, want exactly 1", op.AuditInteractionRenderFailed, len(failures))
	}
	if got := failures[0]["prompt_type"]; got != consent.PromptType {
		t.Errorf("extras.prompt_type=%v, want %q (the prompt that could not be rendered)", got, consent.PromptType)
	}
	if got, _ := failures[0]["error"].(string); !strings.Contains(got, errConsentTemplateBroken.Error()) {
		t.Errorf("extras.error=%q, want it to carry the Driver's cause %q", got, errConsentTemplateBroken)
	}
}

// errServerErrorCode is the OAuth wire code an unrenderable prompt is
// reported under. It is spelled out here rather than imported because
// the endpoint's own constant is unexported.
const errServerErrorCode = "server_error"
