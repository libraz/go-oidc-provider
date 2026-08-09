package tokenexchange_test

// Test file drives RFC 8693 token exchange with an id_token as the
// subject_token against a fully wired provider. Every subject_token the
// assertions consume is minted by the OP's own authorization-code path,
// and the consent that bounds it is written by the OP's own /authorize
// path, so a shape the provider cannot actually produce cannot reach
// the exchange. A hand-assembled id_token would prove nothing here: it
// can carry claims this OP never emits, which is precisely how an
// unreachable code path passes its tests.
//
// Spec:
//   - RFC 8693 §2.1 / §3 — subject_token and its token-type URN
//   - OIDC Core 1.0 §2 — the id_token claim set (which defines no scope)

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

const (
	// txClientSecret is the deterministic confidential-client secret the
	// rows below reuse. A fixed fixture keeps a failure replayable.
	txClientSecret = "tx-idtoken-client-secret" //nolint:gosec // G101: fixture client secret for a test provider, never a live credential.

	txClientID    = "tx-idtoken-rp"
	txRedirectURI = "https://rp.testkit.invalid/callback"
	txSubject     = "user-tx-idtoken"
	txResource    = "https://api.tx.example"

	// txConsentedScope is what the end-user approves during the
	// authorization-code flow, and therefore the exact bound the
	// exchange must respect. "email" is registered on the client but
	// deliberately left out so the rows can tell "the client may ask for
	// it" apart from "the user consented to it".
	txConsentedScope = "openid profile"

	// txPKCEVerifier is a fixed RFC 7636 §4.1 verifier (58 characters
	// from the unreserved alphabet, inside the 43..128 bound). A
	// constant keeps the flow deterministic and the package free of
	// crypto/rand.
	txPKCEVerifier = "tokenexchange-verifier-tokenexchange-verifier-0123456789ab"

	txCSRFCookieName = "__Host-oidc_csrf"

	// txTokenTypeIDToken is the RFC 8693 §3 token-type URN naming an
	// id_token as the subject_token.
	txTokenTypeIDToken = "urn:ietf:params:oauth:token-type:id_token" //nolint:gosec // RFC 8693 token type URN, not a credential.
)

// exchangeObservation is the plain-data copy of what the provider handed
// the policy on the most recent admission call.
type exchangeObservation struct {
	called        bool
	subjectScope  []string
	subjectType   string
	requestScope  []string
	subjectClient string
}

// recordingExchangePolicy admits every exchange with the provider's own
// defaults and keeps a copy of what the provider computed, so a row can
// assert on the subject-token view the OP resolved rather than only on
// the wire envelope.
type recordingExchangePolicy struct {
	mu   sync.Mutex
	seen exchangeObservation
}

func (p *recordingExchangePolicy) Allow(_ context.Context, req op.TokenExchangeRequest) (*op.TokenExchangeDecision, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.seen = exchangeObservation{
		called:        true,
		subjectScope:  slices.Clone(req.SubjectToken.Scope),
		subjectType:   req.SubjectToken.Type,
		subjectClient: req.SubjectToken.ClientID,
		requestScope:  slices.Clone(req.RequestedScope),
	}
	return nil, nil //nolint:nilnil // contract: (nil, nil) means "use OP defaults".
}

func (p *recordingExchangePolicy) snapshot() exchangeObservation {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := p.seen
	out.subjectScope = slices.Clone(p.seen.subjectScope)
	out.requestScope = slices.Clone(p.seen.requestScope)
	return out
}

// TestTokenExchange_IDTokenSubjectToken_ScopeComesFromTheGrant is the
// reachability row: an id_token the OP minted, exchanged with no scope
// parameter at all, must succeed and must be bounded by the consent
// recorded for the (subject, client) pair. An id_token carries no scope
// claim, so a subject view built from the token alone leaves the bound
// empty and every downstream gate refuses the request.
func TestTokenExchange_IDTokenSubjectToken_ScopeComesFromTheGrant(t *testing.T) {
	t.Parallel()

	policy := &recordingExchangePolicy{}
	tk, rp := newExchangeProvider(t, policy)
	idToken := issueIDToken(t, tk, rp)

	status, body := postToken(t, tk, url.Values{
		"grant_type":         {op.TokenExchangeGrantType},
		"subject_token":      {idToken},
		"subject_token_type": {txTokenTypeIDToken},
		"audience":           {txResource},
	})
	if status != http.StatusOK {
		t.Fatalf("status=%d want 200, body=%v", status, body)
	}
	if at, _ := body["access_token"].(string); at == "" {
		t.Errorf("access_token missing from the exchange response: %v", body)
	}
	// The subject_token was an id_token and the granted scope carries
	// openid, so the provider's default is to mint an id_token too.
	if idt, _ := body["id_token"].(string); idt == "" {
		t.Errorf("id_token missing from the exchange response: %v", body)
	}

	got := policy.snapshot()
	if !got.called {
		t.Fatal("policy was never invoked; the exchange short-circuited before admission")
	}
	if got.subjectType != txTokenTypeIDToken {
		t.Errorf("SubjectToken.Type=%q want the id_token urn", got.subjectType)
	}
	if got.subjectClient != rp.ID {
		t.Errorf("SubjectToken.ClientID=%q want %q", got.subjectClient, rp.ID)
	}
	wantScope := strings.Fields(txConsentedScope)
	if !sameScopeSet(got.subjectScope, wantScope) {
		t.Errorf("SubjectToken.Scope=%v want the consented set %v", got.subjectScope, wantScope)
	}
	if !sameScopeSet(got.requestScope, wantScope) {
		t.Errorf("RequestedScope=%v want the consented set %v (scope parameter omitted)", got.requestScope, wantScope)
	}
}

// TestTokenExchange_IDTokenSubjectToken_RejectsScopeBeyondTheGrant
// pins the bound in the other direction. "email" is registered on the
// client, so a bound taken from the client's registration alone would
// admit it; only the consent the id_token was issued under excludes it.
func TestTokenExchange_IDTokenSubjectToken_RejectsScopeBeyondTheGrant(t *testing.T) {
	t.Parallel()

	tk, rp := newExchangeProvider(t, &recordingExchangePolicy{})
	idToken := issueIDToken(t, tk, rp)

	status, body := postToken(t, tk, url.Values{
		"grant_type":         {op.TokenExchangeGrantType},
		"subject_token":      {idToken},
		"subject_token_type": {txTokenTypeIDToken},
		"audience":           {txResource},
		"scope":              {"email"},
	})
	if status != http.StatusBadRequest {
		t.Fatalf("status=%d want 400, body=%v", status, body)
	}
	if got := body["error"]; got != "invalid_scope" {
		t.Errorf("error=%v want invalid_scope", got)
	}
}

// TestTokenExchange_IDTokenSubjectToken_WithdrawnConsentRejected is the
// revocation row. The id_token stays cryptographically valid and
// unexpired for the whole test, so nothing but the consent lookup can
// refuse it: withdrawing the grant MUST close the exchange immediately
// rather than leaving the token exchangeable until its own exp.
func TestTokenExchange_IDTokenSubjectToken_WithdrawnConsentRejected(t *testing.T) {
	t.Parallel()

	tk, rp := newExchangeProvider(t, &recordingExchangePolicy{})
	idToken := issueIDToken(t, tk, rp)
	exchange := url.Values{
		"grant_type":         {op.TokenExchangeGrantType},
		"subject_token":      {idToken},
		"subject_token_type": {txTokenTypeIDToken},
		"audience":           {txResource},
	}

	// Establish the same request succeeds while the consent stands, so
	// the assertion below cannot pass for an unrelated reason.
	if status, body := postToken(t, tk, exchange); status != http.StatusOK {
		t.Fatalf("pre-revocation status=%d want 200, body=%v", status, body)
	}

	withdrawConsent(t, tk, rp.ID)

	status, body := postToken(t, tk, exchange)
	if status != http.StatusBadRequest {
		t.Fatalf("post-revocation status=%d want 400, body=%v", status, body)
	}
	if got := body["error"]; got != "invalid_grant" {
		t.Errorf("error=%v want invalid_grant", got)
	}
}

// newExchangeProvider wires a provider with the token-exchange grant
// enrolled and a confidential client registered for both the
// authorization-code flow (which mints the id_token) and the exchange
// (which consumes it).
func newExchangeProvider(t *testing.T, policy op.TokenExchangePolicy) (*testkit.Provider, *store.Client) {
	t.Helper()
	hash, err := op.HashClientSecret(txClientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	tk := testkit.NewProvider(t, testkit.WithOptions(op.RegisterTokenExchange(policy)))
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      txClientID,
		SecretHash:              hash,
		TokenEndpointAuthMethod: "client_secret_basic",
		RedirectURIs:            []string{txRedirectURI},
		GrantTypes:              []string{"authorization_code", op.TokenExchangeGrantType},
		ResponseTypes:           []string{"code"},
		Scopes:                  []string{"openid", "profile", "email"},
		Resources:               []string{txResource},
	})
	return tk, rp
}

// issueIDToken drives /authorize through the interaction chain to the
// callback, redeems the resulting code at /token, and returns the
// id_token the provider minted. Both artefacts the exchange depends on
// -- the signed id_token and the durable grant recording the approved
// scope -- are produced here by the provider itself.
func issueIDToken(t *testing.T, tk *testkit.Provider, rp *store.Client) string {
	t.Helper()
	code := runCodeFlow(t, tk, rp)
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {txRedirectURI},
		"code_verifier": {txPKCEVerifier},
	}
	status, body := postToken(t, tk, form)
	if status != http.StatusOK {
		t.Fatalf("code redemption status=%d want 200, body=%v", status, body)
	}
	idToken, _ := body["id_token"].(string)
	if idToken == "" {
		t.Fatalf("code redemption returned no id_token: %v", body)
	}
	return idToken
}

// runCodeFlow walks /authorize -> /interaction (subject) -> /interaction
// (consent) -> callback and returns the authorization code.
func runCodeFlow(t *testing.T, tk *testkit.Provider, rp *store.Client) string {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	client := tk.HTTPClient(jar)

	sum := sha256.Sum256([]byte(txPKCEVerifier))
	query := url.Values{
		"client_id":             {rp.ID},
		"response_type":         {"code"},
		"redirect_uri":          {txRedirectURI},
		"scope":                 {txConsentedScope},
		"state":                 {"tx-idtoken-state"},
		"nonce":                 {"tx-idtoken-nonce"},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	authResp := doGet(t, client, tk.Server.URL+"/oidc/auth?"+query.Encode())
	defer func() { _ = authResp.Body.Close() }()
	if authResp.StatusCode != http.StatusFound {
		t.Fatalf("/authorize status=%d want 302", authResp.StatusCode)
	}
	location, err := authResp.Location()
	if err != nil {
		t.Fatalf("/authorize Location: %v", err)
	}
	if !strings.HasPrefix(location.Path, "/oidc/interaction/") {
		t.Fatalf("/authorize Location=%s want an interaction URL", location)
	}
	interactionURL := tk.Server.URL + location.Path

	promptResp := doGet(t, client, interactionURL)
	defer func() { _ = promptResp.Body.Close() }()
	if promptResp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s status=%d want 200", interactionURL, promptResp.StatusCode)
	}
	prompt := decodeBody(t, promptResp)
	stateRef, _ := prompt["state_ref"].(string)
	if stateRef == "" {
		t.Fatal("interaction prompt carries no state_ref")
	}
	csrf := cookieNamed(promptResp.Cookies(), txCSRFCookieName)
	if csrf == nil {
		t.Fatalf("interaction prompt set no %s cookie", txCSRFCookieName)
	}

	authStep := postInteraction(t, client, interactionURL, tk.Issuer, csrf.Value, stateRef,
		map[string]string{testkit.SubjectFieldName: txSubject})
	final := approveConsent(t, client, interactionURL, tk.Issuer, csrf.Value, authStep)
	defer func() { _ = final.Body.Close() }()
	if final.StatusCode != http.StatusFound {
		raw, _ := io.ReadAll(final.Body)
		t.Fatalf("final interaction status=%d body=%s", final.StatusCode, raw)
	}
	callback, err := final.Location()
	if err != nil {
		t.Fatalf("final Location: %v", err)
	}
	code := callback.Query().Get("code")
	if code == "" {
		t.Fatalf("callback %s carries no code", callback)
	}
	return code
}

// approveConsent submits the built-in consent screen with every
// requested scope approved when prior is a consent prompt, and returns
// the chain's next response. A prior that is already the final redirect
// passes through unchanged.
func approveConsent(t *testing.T, client *http.Client, interactionURL, origin, csrf string, prior *http.Response) *http.Response {
	t.Helper()
	// The consent check drains prior.Body, so pull the rotated CSRF
	// cookie off the response before it is consumed. Each interaction
	// step re-issues the cookie, so the value minted at the
	// authentication step does not verify against the consent step.
	if rotated := cookieNamed(prior.Cookies(), txCSRFCookieName); rotated != nil {
		csrf = rotated.Value
	}
	consent, envelope, err := testkit.IsConsentPrompt(prior)
	if err != nil {
		t.Fatalf("inspect consent prompt: %v", err)
	}
	if !consent {
		return prior
	}
	defer func() { _ = prior.Body.Close() }()
	stateRef, _ := envelope["state_ref"].(string)
	if stateRef == "" {
		t.Fatal("consent prompt carries no state_ref")
	}
	return testkit.PostConsentApproval(t, client, interactionURL, origin, csrf, stateRef,
		strings.Join(promptScopes(envelope), " "))
}

// promptScopes lists the scope names the consent prompt asked about.
func promptScopes(envelope map[string]any) []string {
	data, _ := envelope["data"].(map[string]any)
	entries, _ := data["Scopes"].([]any)
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		fields, _ := entry.(map[string]any)
		if name, _ := fields["Name"].(string); name != "" {
			out = append(out, name)
		}
	}
	return out
}

// withdrawConsent deletes the durable grant the code flow recorded for
// (txSubject, clientID) — the state a consent-revocation surface leaves
// behind.
func withdrawConsent(t *testing.T, tk *testkit.Provider, clientID string) {
	t.Helper()
	ctx := t.Context()
	grant, err := tk.Store.Grants().FindBySubjectClient(ctx, txSubject, clientID)
	if err != nil {
		t.Fatalf("FindBySubjectClient(%q, %q): %v", txSubject, clientID, err)
	}
	if err := tk.Store.Grants().Delete(ctx, grant.ID); err != nil {
		t.Fatalf("Delete(%q): %v", grant.ID, err)
	}
}

// postToken submits form to /token with HTTP Basic client
// authentication and returns the (status, decoded body) pair.
func postToken(t *testing.T, tk *testkit.Provider, form url.Values) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		tk.Server.URL+"/oidc/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("build /token request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(txClientID, txClientSecret)
	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("POST /token: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode, decodeBody(t, resp)
}

// postInteraction submits a JSON {state_ref, values} envelope to the
// interaction endpoint, threading the CSRF cookie / header pair the
// OP's middleware enforces.
func postInteraction(t *testing.T, client *http.Client, interactionURL, origin, csrf, stateRef string, values map[string]string) *http.Response {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"state_ref": stateRef, "values": values})
	if err != nil {
		t.Fatalf("marshal interaction submission: %v", err)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, interactionURL, bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("build interaction request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", origin)
	req.Header.Set("X-CSRF-Token", csrf)
	req.AddCookie(&http.Cookie{Name: txCSRFCookieName, Value: csrf})
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", interactionURL, err)
	}
	return resp
}

// doGet issues a GET and fails the test on transport error.
func doGet(t *testing.T, client *http.Client, rawURL string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, rawURL, http.NoBody)
	if err != nil {
		t.Fatalf("build GET %s: %v", rawURL, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", rawURL, err)
	}
	return resp
}

// decodeBody reads resp.Body as a JSON object. An empty body decodes to
// an empty map so callers see a stable zero value.
func decodeBody(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	out := map[string]any{}
	if len(raw) == 0 {
		return out
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode body %s: %v", raw, err)
	}
	return out
}

// cookieNamed returns the cookie called name, or nil.
func cookieNamed(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// sameScopeSet compares two scope slices as sets: the OP does not
// promise an ordering for the consented scope set, so an order-
// sensitive assertion would be a latent flake.
func sameScopeSet(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	a := slices.Clone(got)
	b := slices.Clone(want)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}
