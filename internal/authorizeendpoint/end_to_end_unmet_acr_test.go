package authorizeendpoint_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// strongACRPolicy is an [op.ACRPolicy] that grants its acr only to a
// ceremony that reached two factors. The testkit chain runs a single
// AAL1 authenticator, so every login under this policy leaves the
// requested context unsatisfied — the shape a deployment sees when a
// relying party asks for step-up the user did not complete.
type strongACRPolicy struct{}

const strongACR = "urn:example:acr:two-factor"

func (strongACRPolicy) Resolve(ctx context.Context, lc op.LoginContext, internal op.AAL) (string, []string, bool) {
	policy := strongACRPolicy{}
	for _, want := range lc.ACRValues {
		if policy.Satisfies(ctx, want, internal, lc.CompletedSteps) {
			return want, nil, true
		}
	}
	return "", nil, false
}

func (strongACRPolicy) Satisfies(_ context.Context, requested string, internal op.AAL, _ []op.StepKind) bool {
	return requested == strongACR && internal >= op.AAL2
}

// TestEndToEnd_EssentialACRUnsatisfiedIsRefused covers the request that
// marks acr essential through the claims parameter and names no
// acr_values at all. Two things have to hold on the wire: the policy is
// applied to the value the claims parameter carried (the OP has no
// other source for it), and a context the policy refuses ends the
// request with unmet_authentication_requirements rather than an
// authorization code carrying no acr claim.
func TestEndToEnd_EssentialACRUnsatisfiedIsRefused(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t,
		testkit.WithClock(fakeClock{now: time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)}),
		testkit.WithOptions(op.WithACRPolicy(strongACRPolicy{})),
	)
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:           "rp-essential-acr",
		RedirectURIs: []string{"https://rp.testkit.invalid/callback"},
		Scopes:       []string{"openid", "profile", "email"},
	})
	values := e2eAuthorizeValues(rp.ID, rp.RedirectURIs[0])
	values.Set("claims", `{"id_token":{"acr":{"essential":true,"values":["`+strongACR+`"]}}}`)

	final := runInteractiveAuthorize(t, tk, values, "user-essential-acr")
	defer final.Body.Close()

	if final.StatusCode != http.StatusFound {
		dump, _ := io.ReadAll(final.Body)
		t.Fatalf("final status=%d body=%s", final.StatusCode, string(dump))
	}
	location, err := final.Location()
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	q := location.Query()
	if got := q.Get("error"); got != "unmet_authentication_requirements" {
		t.Errorf("error = %q, want unmet_authentication_requirements (redirect: %s)", got, location)
	}
	if got := q.Get("code"); got != "" {
		t.Errorf("code = %q, want no code for a refused authentication context", got)
	}
	if got := q.Get("state"); got != values.Get("state") {
		t.Errorf("state = %q, want %q echoed back", got, values.Get("state"))
	}
}

// TestEndToEnd_VoluntaryACRUnsatisfiedStillMints is the contrast case
// that keeps the refusal narrow: acr_values is a voluntary hint, so the
// same unsatisfiable policy verdict yields a normal authorization code
// and the id_token simply carries no acr claim.
func TestEndToEnd_VoluntaryACRUnsatisfiedStillMints(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t,
		testkit.WithClock(fakeClock{now: time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)}),
		testkit.WithOptions(op.WithACRPolicy(strongACRPolicy{})),
	)
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:           "rp-voluntary-acr",
		RedirectURIs: []string{"https://rp.testkit.invalid/callback"},
		Scopes:       []string{"openid", "profile", "email"},
	})
	values := e2eAuthorizeValues(rp.ID, rp.RedirectURIs[0])
	values.Set("acr_values", strongACR)

	final := runInteractiveAuthorize(t, tk, values, "user-voluntary-acr")
	defer final.Body.Close()

	if final.StatusCode != http.StatusFound {
		dump, _ := io.ReadAll(final.Body)
		t.Fatalf("final status=%d body=%s", final.StatusCode, string(dump))
	}
	location, err := final.Location()
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	if got := location.Query().Get("error"); got != "" {
		t.Fatalf("error = %q, want a code for a voluntary acr request (redirect: %s)", got, location)
	}
	if location.Query().Get("code") == "" {
		t.Errorf("no code in %s", location)
	}
}

// TestEndToEnd_ClaimsOnlyACRIsEchoed is the positive half of the
// claims-parameter wiring: an RP that names its authentication context
// only through claims.id_token.acr — no acr_values at all — has that
// value put to the policy, and a policy that accepts it stamps it onto
// the id_token. Resolving from acr_values alone would leave the policy
// with nothing to satisfy and the id_token with no acr.
func TestEndToEnd_ClaimsOnlyACRIsEchoed(t *testing.T) {
	t.Parallel()

	const wantACR = "urn:example:acr:claims-only"
	tk := testkit.NewProvider(t,
		testkit.WithClock(fakeClock{now: time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)}),
	)
	const secret = "rp-secret"
	hasher := clientauth.Argon2id{}
	hash, err := hasher.Hash(secret)
	if err != nil {
		t.Fatalf("Argon2id.Hash: %v", err)
	}
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      "rp-claims-acr",
		SecretHash:              hash,
		RedirectURIs:            []string{"https://rp.testkit.invalid/callback"},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	values := e2eAuthorizeValues(rp.ID, rp.RedirectURIs[0])
	values.Set("claims", `{"id_token":{"acr":{"essential":true,"value":"`+wantACR+`"}}}`)

	final := runInteractiveAuthorize(t, tk, values, "user-claims-acr")
	defer final.Body.Close()
	if final.StatusCode != http.StatusFound {
		dump, _ := io.ReadAll(final.Body)
		t.Fatalf("final status=%d body=%s", final.StatusCode, string(dump))
	}
	location, err := final.Location()
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	code := location.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in %s", location)
	}
	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {rp.RedirectURIs[0]},
		"code_verifier": {e2eVerifier},
	}
	tokenReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+"/oidc/token", strings.NewReader(tokenForm.Encode()))
	if err != nil {
		t.Fatalf("NewRequest token: %v", err)
	}
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenReq.SetBasicAuth(rp.ID, secret)
	tokenResp, err := tk.HTTPClient(nil).Do(tokenReq)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer tokenResp.Body.Close()
	if tokenResp.StatusCode != http.StatusOK {
		dump, _ := io.ReadAll(tokenResp.Body)
		t.Fatalf("token status=%d body=%s", tokenResp.StatusCode, string(dump))
	}
	idt, _ := decodeMap(t, tokenResp)["id_token"].(string)
	if idt == "" {
		t.Fatal("id_token missing")
	}
	if got, _ := decodeIDTokenPayload(t, idt)["acr"].(string); got != wantACR {
		t.Errorf("id_token acr = %q, want %q", got, wantACR)
	}
}

// runInteractiveAuthorize drives one browser-shaped authorize run: the
// /authorize redirect, the interaction GET that emits the first prompt,
// the submission that binds subject, and any consent step behind it. It
// returns the response that closes the interaction, which is either the
// success redirect or the error redirect.
func runInteractiveAuthorize(t *testing.T, tk *testkit.Provider, values interface{ Encode() string }, subject string) *http.Response {
	t.Helper()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	client := tk.HTTPClient(jar)
	authResp, err := newGet(tk.Server.URL + "/oidc/auth?" + values.Encode()).Do(client)
	if err != nil {
		t.Fatalf("GET /authorize: %v", err)
	}
	defer authResp.Body.Close()
	if authResp.StatusCode != http.StatusFound {
		dump, _ := io.ReadAll(authResp.Body)
		t.Fatalf("authorize status=%d body=%s", authResp.StatusCode, string(dump))
	}
	location, err := authResp.Location()
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	stepResp, err := newGet(tk.Server.URL + location.Path).Do(client)
	if err != nil {
		t.Fatalf("GET interaction: %v", err)
	}
	defer stepResp.Body.Close()
	step := decodeMap(t, stepResp)
	stateRef, _ := step["state_ref"].(string)
	csrfCookie := findCookie(stepResp.Cookies(), "__Host-oidc_csrf")
	if csrfCookie == nil {
		t.Fatal("csrf cookie missing")
	}
	raw, err := json.Marshal(map[string]any{
		"state_ref": stateRef,
		"values":    map[string]string{"subject": subject},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	postReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		tk.Server.URL+location.Path, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	postReq.Header.Set("Content-Type", "application/json")
	postReq.Header.Set("Origin", tk.Issuer)
	postReq.Header.Set("X-CSRF-Token", csrfCookie.Value)
	postReq.AddCookie(csrfCookie)
	postResp, err := client.Do(postReq)
	if err != nil {
		t.Fatalf("POST interaction: %v", err)
	}
	defer postResp.Body.Close()
	return completeConsentIfPrompted(t, client, tk.Server.URL+location.Path, tk.Issuer, csrfCookie.Value, postResp)
}
