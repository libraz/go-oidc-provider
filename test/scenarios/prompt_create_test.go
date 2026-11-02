package scenarios_test

// Catalog: test/scenarios/catalog/prompt_create.yaml (PCR-NNN)
// Spec:
//   - OpenID Connect Initiating User Registration 1.0 §4.1, §4.2 — prompt=create
//   - OIDC Core 1.0 §3.1.2.1 (prompt), §3.1.2.6 (Authentication Error Response)
//   - RFC 9126 — PAR
//   - RFC 9101 — JAR

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

const (
	pcrClientID     = "rp-pcr"
	pcrClientSecret = "rp-pcr-secret" //nolint:gosec // G101: test fixture, not a real credential.
	pcrCallback     = "https://rp.testkit.invalid/callback"
	pcrState        = "pcr-state"
	pcrKeyID        = "rp-pcr-kid"

	pcrLoginSubject = "user-existing"
	pcrNewSubject   = "user-registered"

	pcrRegisterPrompt = "auth.test.register"
	pcrRegisterField  = "new_subject"
	pcrWelcomePrompt  = "auth.test.welcome"

	pcrKindRegister = op.StepKind("test.register")
	pcrKindWelcome  = op.StepKind("test.welcome")

	pcrDescUnrecognised   = "prompt contains an unrecognised value"
	pcrDescNoneConflict   = "prompt=none cannot combine with other prompts"
	pcrDescCreateConflict = "prompt=create cannot combine with other prompts"

	pcrConsentPrompt = "consent.scope"
)

// pcrClock is a movable op.Clock: the scenarios advance it between hops so
// the attempt's auth_time differs from both the interaction creation time
// and the session's.
type pcrClock struct {
	mu  sync.Mutex
	now time.Time
}

func newPCRClock() *pcrClock {
	return &pcrClock{now: time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)}
}

func (c *pcrClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *pcrClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// pcrPrimary is the ordinary login factor: it binds the subject named in the
// submission, stamps AuthTime from the clock, and counts its Begin calls.
type pcrPrimary struct {
	clock *pcrClock
	users interface {
		PutUser(context.Context, *store.User)
	}
	begins atomic.Int32
}

func (*pcrPrimary) Type() op.FactorType { return op.FactorPassword }
func (*pcrPrimary) AAL() op.AAL         { return op.AAL1 }
func (*pcrPrimary) AMR() string         { return "pwd" }
func (*pcrPrimary) Prompts() []string   { return []string{testkit.SubjectPromptType} }

func (p *pcrPrimary) Begin(context.Context, op.BeginInput) (interaction.Step, error) {
	p.begins.Add(1)
	return interaction.Step{Prompt: pcrTextPrompt(testkit.SubjectPromptType, testkit.SubjectFieldName)}, nil
}

func (p *pcrPrimary) Continue(ctx context.Context, in op.ContinueInput) (interaction.Step, error) {
	sub := in.Submission.Values[testkit.SubjectFieldName]
	if sub == "" {
		return interaction.Step{}, testkit.ErrSubjectMissing
	}
	p.users.PutUser(ctx, &store.User{Subject: sub})
	return interaction.Step{Result: &interaction.Result{Subject: sub, AuthTime: p.clock.Now()}}, nil
}

// pcrRegister stands in for the embedder's account-creation step. It
// records the subject Begin was handed (an inherited subject would show up
// there) and binds the subject the submission names.
type pcrRegister struct {
	clock *pcrClock
	users interface {
		PutUser(context.Context, *store.User)
	}
	begins       atomic.Int32
	beginSubject atomic.Pointer[string]
}

func (*pcrRegister) Type() op.FactorType { return "test.register" }
func (*pcrRegister) AAL() op.AAL         { return op.AAL1 }
func (*pcrRegister) AMR() string         { return "otp" }
func (*pcrRegister) Prompts() []string   { return []string{pcrRegisterPrompt} }

func (r *pcrRegister) Begin(_ context.Context, in op.BeginInput) (interaction.Step, error) {
	r.begins.Add(1)
	seen := in.Subject
	r.beginSubject.Store(&seen)
	return interaction.Step{Prompt: pcrTextPrompt(pcrRegisterPrompt, pcrRegisterField)}, nil
}

func (r *pcrRegister) Continue(ctx context.Context, in op.ContinueInput) (interaction.Step, error) {
	sub := in.Submission.Values[pcrRegisterField]
	if sub == "" {
		return interaction.Step{}, testkit.ErrSubjectMissing
	}
	r.users.PutUser(ctx, &store.User{Subject: sub})
	return interaction.Step{Result: &interaction.Result{Subject: sub, AuthTime: r.clock.Now()}}, nil
}

// pcrWelcome is a post-registration step a Rule schedules; it binds nothing
// new and passes the subject through.
type pcrWelcome struct{ begins atomic.Int32 }

func (*pcrWelcome) Type() op.FactorType { return "test.welcome" }
func (*pcrWelcome) AAL() op.AAL         { return op.AAL1 }
func (*pcrWelcome) AMR() string         { return "pwd" }
func (*pcrWelcome) Prompts() []string   { return []string{pcrWelcomePrompt} }

func (w *pcrWelcome) Begin(context.Context, op.BeginInput) (interaction.Step, error) {
	w.begins.Add(1)
	return interaction.Step{Prompt: pcrTextPrompt(pcrWelcomePrompt, "ack")}, nil
}

func (*pcrWelcome) Continue(_ context.Context, in op.ContinueInput) (interaction.Step, error) {
	return interaction.Step{Result: &interaction.Result{Subject: in.Subject, AuthTime: in.AuthTime}}, nil
}

func pcrTextPrompt(promptType, field string) *interaction.Prompt {
	return &interaction.Prompt{
		Type: promptType,
		Inputs: []interaction.FieldSpec{{
			Name:     field,
			Kind:     interaction.FieldText,
			Required: true,
			MinLen:   1,
			MaxLen:   256,
		}},
	}
}

type pcrRoute int

const (
	pcrPlain pcrRoute = iota
	pcrPAR
	pcrJAR
)

func (r pcrRoute) String() string { return [...]string{"plain", "par", "jar"}[r] }

// pcrFixture is a Provider with PAR and JAR on, a confidential client with
// an ES256 JWKS, and a LoginFlow whose Primary and (optionally) Registration
// are the recording authenticators above.
type pcrFixture struct {
	t        *testing.T
	tk       *testkit.Provider
	clock    *pcrClock
	cl       *http.Client
	priv     *ecdsa.PrivateKey
	primary  *pcrPrimary
	register *pcrRegister
	welcome  *pcrWelcome
}

func pcrFlow(clock *pcrClock, users interface {
	PutUser(context.Context, *store.User)
}, withRegistration bool,
	welcome *pcrWelcome,
) (op.LoginFlow, *pcrPrimary, *pcrRegister) {
	primary := &pcrPrimary{clock: clock, users: users}
	register := &pcrRegister{clock: clock, users: users}
	flow := op.LoginFlow{Primary: op.ExternalStep{Authenticator: primary, KindLabel: op.StepKind("test.primary")}}
	if withRegistration {
		flow.Registration = op.ExternalStep{Authenticator: register, KindLabel: pcrKindRegister}
	}
	if welcome != nil {
		flow.Rules = []op.Rule{op.RuleWhen(func(lc op.LoginContext) bool {
			return slices.Contains(lc.CompletedSteps, pcrKindRegister)
		}, op.ExternalStep{Authenticator: welcome, KindLabel: pcrKindWelcome})}
	}
	return flow, primary, register
}

func newPCRFixture(t *testing.T, withRegistration, withWelcome bool) *pcrFixture {
	t.Helper()
	clock := newPCRClock()
	st := newPCRUserSink()
	var welcome *pcrWelcome
	if withWelcome {
		welcome = &pcrWelcome{}
	}
	flow, primary, register := pcrFlow(clock, st, withRegistration, welcome)
	tk := testkit.NewProvider(t,
		testkit.WithClock(clock),
		testkit.WithOptions(
			op.WithLoginFlow(flow),
			op.WithFeature(feature.PAR),
			op.WithFeature(feature.JAR),
		),
	)
	st.target = tk.Store

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate RP key: %v", err)
	}
	jwks, err := json.Marshal(josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{{
		Key: &priv.PublicKey, KeyID: pcrKeyID, Algorithm: string(josev4.ES256), Use: "sig",
	}}})
	if err != nil {
		t.Fatalf("marshal RP JWKS: %v", err)
	}
	hash, err := op.HashClientSecret(pcrClientSecret)
	if err != nil {
		t.Fatalf("HashClientSecret: %v", err)
	}
	tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      pcrClientID,
		SecretHash:              hash,
		RedirectURIs:            []string{pcrCallback},
		Scopes:                  []string{"openid", "profile"},
		TokenEndpointAuthMethod: "client_secret_basic",
		JWKs:                    jwks,
	})
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	return &pcrFixture{
		t: t, tk: tk, clock: clock, cl: tk.HTTPClient(jar), priv: priv,
		primary: primary, register: register, welcome: welcome,
	}
}

// pcrUserSink forwards PutUser to the provider's store once it exists; the
// authenticators are built before the store is.
type pcrUserSink struct {
	target interface {
		PutUser(context.Context, *store.User)
	}
}

func newPCRUserSink() *pcrUserSink { return &pcrUserSink{} }

func (s *pcrUserSink) PutUser(ctx context.Context, u *store.User) { s.target.PutUser(ctx, u) }

// pcrAuthz describes one authorization request.
type pcrAuthz struct {
	route  pcrRoute
	prompt string
	// promptArray, for the JAR route, sends prompt as a JSON array claim.
	promptArray []string
	scope       string
}

// pcrAuthzOut is the first response of an authorization request.
type pcrAuthzOut struct {
	pkce scenariokit.PKCEPair
	// loc is the /authorize redirect target; nil when the request ended
	// before one existed (a PAR push refusal).
	loc *url.URL
	// status and body describe a non-redirect answer (the PAR 400).
	status int
	body   map[string]any
}

func (f *pcrFixture) authorize(r pcrAuthz) pcrAuthzOut {
	f.t.Helper()
	pkce := scenariokit.NewPKCEPair("")
	scope := r.scope
	if scope == "" {
		scope = "openid"
	}
	params := url.Values{
		"client_id":             {pcrClientID},
		"response_type":         {"code"},
		"redirect_uri":          {pcrCallback},
		"scope":                 {scope},
		"state":                 {pcrState},
		"nonce":                 {"pcr-nonce"},
		"code_challenge":        {pkce.Challenge},
		"code_challenge_method": {pkce.Method},
	}
	if r.prompt != "" {
		params.Set("prompt", r.prompt)
	}
	out := pcrAuthzOut{pkce: pkce}
	var authQuery url.Values
	switch r.route {
	case pcrPlain:
		authQuery = params
	case pcrPAR:
		resp := f.postForm("/oidc/par", params)
		defer resp.Body.Close()
		out.status = resp.StatusCode
		out.body = scenariokit.DecodeJSON(f.t, resp)
		if resp.StatusCode != http.StatusCreated {
			return out
		}
		uri, _ := out.body["request_uri"].(string)
		authQuery = url.Values{"client_id": {pcrClientID}, "request_uri": {uri}}
	case pcrJAR:
		claims := map[string]any{
			"iss": pcrClientID, "aud": f.tk.Issuer,
			"iat": f.clock.Now().Unix(), "nbf": f.clock.Now().Unix(), "exp": f.clock.Now().Add(2 * time.Minute).Unix(),
			"jti": pcrJTI(f.t),
		}
		for k, v := range params {
			claims[k] = v[0]
		}
		if r.promptArray != nil {
			claims["prompt"] = r.promptArray
		}
		authQuery = url.Values{
			"client_id": {pcrClientID}, "response_type": {"code"},
			"request": {f.signRequestObject(claims)},
		}
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		f.tk.Server.URL+"/oidc/auth?"+authQuery.Encode(), http.NoBody)
	if err != nil {
		f.t.Fatalf("build /authorize: %v", err)
	}
	resp, err := f.cl.Do(req)
	if err != nil {
		f.t.Fatalf("GET /authorize: %v", err)
	}
	defer resp.Body.Close()
	out.status = resp.StatusCode
	if resp.StatusCode != http.StatusFound {
		out.body = scenariokit.DecodeJSON(f.t, resp)
		return out
	}
	loc, err := resp.Location()
	if err != nil {
		f.t.Fatalf("/authorize Location: %v", err)
	}
	out.loc = loc
	return out
}

func (f *pcrFixture) postForm(path string, form url.Values) *http.Response {
	f.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		f.tk.Server.URL+path, strings.NewReader(form.Encode()))
	if err != nil {
		f.t.Fatalf("build POST %s: %v", path, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(pcrClientID, pcrClientSecret)
	resp, err := f.cl.Do(req)
	if err != nil {
		f.t.Fatalf("POST %s: %v", path, err)
	}
	return resp
}

func (f *pcrFixture) signRequestObject(claims map[string]any) string {
	f.t.Helper()
	signer, err := josev4.NewSigner(josev4.SigningKey{
		Algorithm: josev4.ES256,
		Key:       josev4.JSONWebKey{Key: f.priv, KeyID: pcrKeyID, Algorithm: string(josev4.ES256), Use: "sig"},
	}, (&josev4.SignerOptions{}).WithType("oauth-authz-req+jwt"))
	if err != nil {
		f.t.Fatalf("NewSigner: %v", err)
	}
	out, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		f.t.Fatalf("sign request object: %v", err)
	}
	return out
}

func pcrJTI(tb testing.TB) string {
	tb.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		tb.Fatalf("jti: %v", err)
	}
	return "pcr-jti-" + hex.EncodeToString(b[:])
}

// pcrWalk is what an interaction walk observed.
type pcrWalk struct {
	// redirect is the final RP redirect.
	redirect *url.URL
	// seen lists the prompt types shown, in order (consent included).
	seen []string
	// submittedAt is the clock reading at the first non-consent submission.
	submittedAt time.Time
}

// walk drives loc to the RP redirect: every non-consent prompt is answered
// from answers (keyed by prompt type), consent is approved as shown. The
// clock advances 5 minutes before the first answer so the credential time
// differs from the interaction's creation time.
func (f *pcrFixture) walk(loc *url.URL, answers map[string][]string) pcrWalk {
	f.t.Helper()
	var w pcrWalk
	if !strings.HasPrefix(loc.Path, "/oidc/interaction/") {
		w.redirect = loc
		return w
	}
	path := loc.Path
	resp := pcrGet(f.t, f.cl, f.tk.Server.URL+path)
	var csrf string
	advanced := false
	for range 8 {
		if c := scenariokit.FindCookie(resp.Cookies(), "__Host-oidc_csrf"); c != nil {
			csrf = c.Value
		}
		if resp.StatusCode == http.StatusFound {
			l, err := resp.Location()
			resp.Body.Close()
			if err != nil {
				f.t.Fatalf("interaction Location: %v", err)
			}
			w.redirect = l
			return w
		}
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			f.t.Fatalf("interaction status=%d body=%s (seen %v)", resp.StatusCode, body, w.seen)
		}
		env := scenariokit.DecodeJSON(f.t, resp)
		resp.Body.Close()
		typ, _ := env["type"].(string)
		stateRef, _ := env["state_ref"].(string)
		w.seen = append(w.seen, typ)
		if typ == pcrConsentPrompt {
			resp = testkit.PostConsentApproval(f.t, f.cl, f.tk.Server.URL+path, f.tk.Issuer,
				csrf, stateRef, testkit.ApprovedScopesFrom(f.t, env))
			continue
		}
		vals, ok := answers[typ]
		if !ok {
			f.t.Fatalf("no answer prepared for prompt %q (seen %v)", typ, w.seen)
		}
		if !advanced {
			f.clock.Advance(5 * time.Minute)
			w.submittedAt = f.clock.Now()
			advanced = true
		}
		resp = f.submit(path, csrf, stateRef, map[string]string{vals[0]: vals[1]})
	}
	f.t.Fatalf("interaction did not terminate (seen %v)", w.seen)
	return w
}

func (f *pcrFixture) submit(path, csrf, stateRef string, values map[string]string) *http.Response {
	f.t.Helper()
	raw, err := json.Marshal(map[string]any{"state_ref": stateRef, "values": values})
	if err != nil {
		f.t.Fatalf("marshal submission: %v", err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		f.tk.Server.URL+path, bytes.NewReader(raw))
	if err != nil {
		f.t.Fatalf("build submission: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", f.tk.Issuer)
	req.Header.Set("X-CSRF-Token", csrf)
	req.AddCookie(&http.Cookie{Name: "__Host-oidc_csrf", Value: csrf})
	resp, err := f.cl.Do(req)
	if err != nil {
		f.t.Fatalf("POST interaction: %v", err)
	}
	return resp
}

// answers returns the prepared answers for the Primary and Registration
// prompts (and the welcome step).
func pcrAnswers() map[string][]string {
	return map[string][]string{
		testkit.SubjectPromptType: {testkit.SubjectFieldName, pcrLoginSubject},
		pcrRegisterPrompt:         {pcrRegisterField, pcrNewSubject},
		pcrWelcomePrompt:          {"ack", "ok"},
	}
}

// exchange redeems the code on redirect and returns the id_token claims.
func (f *pcrFixture) exchange(pkce scenariokit.PKCEPair, redirect *url.URL) map[string]any {
	f.t.Helper()
	code := redirect.Query().Get("code")
	if code == "" {
		f.t.Fatalf("no code in RP redirect %s", redirect)
	}
	tok := scenariokit.ExchangeCode(f.t, f.tk, scenariokit.ExchangeCodeRequest{
		Code: code, RedirectURI: pcrCallback, Verifier: pkce.Verifier,
		ClientID: pcrClientID, ClientSecret: pcrClientSecret,
	})
	if tok.StatusCode != http.StatusOK || tok.IDToken == "" {
		f.t.Fatalf("/token status=%d body=%v", tok.StatusCode, tok.Raw)
	}
	return scenariokit.DecodeJWSClaims(f.t, tok.IDToken)
}

// login establishes a session for pcrLoginSubject with a grant for "openid"
// and returns the session's auth_time.
func (f *pcrFixture) login() int64 {
	f.t.Helper()
	out := f.authorize(pcrAuthz{route: pcrPlain})
	w := f.walk(out.loc, pcrAnswers())
	claims := f.exchange(out.pkce, w.redirect)
	if got, _ := claims["sub"].(string); got != pcrLoginSubject {
		f.t.Fatalf("session login sub=%q want %q", got, pcrLoginSubject)
	}
	at, _ := claims["auth_time"].(float64)
	if int64(at) != w.submittedAt.Unix() {
		f.t.Fatalf("session auth_time=%d want %d", int64(at), w.submittedAt.Unix())
	}
	return int64(at)
}

func pcrGet(tb testing.TB, cl *http.Client, rawURL string) *http.Response {
	tb.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, rawURL, http.NoBody)
	if err != nil {
		tb.Fatalf("build GET %s: %v", rawURL, err)
	}
	resp, err := cl.Do(req)
	if err != nil {
		tb.Fatalf("GET %s: %v", rawURL, err)
	}
	return resp
}

// requireRPError asserts out is the invalid_request refusal with desc:
// a 400 envelope from /par on the PAR route, an RP redirect carrying the
// error and the echoed state otherwise.
func (f *pcrFixture) requireRPError(label string, route pcrRoute, out pcrAuthzOut, desc string) {
	f.t.Helper()
	if route == pcrPAR {
		if out.status != http.StatusBadRequest {
			f.t.Fatalf("%s: /par status=%d want 400 (body %v)", label, out.status, out.body)
		}
		if got, _ := out.body["error"].(string); got != "invalid_request" {
			f.t.Errorf("%s: /par error=%q want invalid_request", label, got)
		}
		if got, _ := out.body["error_description"].(string); got != desc {
			f.t.Errorf("%s: /par error_description=%q want %q", label, got, desc)
		}
		return
	}
	if out.loc == nil {
		f.t.Fatalf("%s: /authorize status=%d body=%v, want an RP error redirect", label, out.status, out.body)
	}
	if got := out.loc.Scheme + "://" + out.loc.Host + out.loc.Path; got != pcrCallback {
		f.t.Fatalf("%s: redirect target=%q want RP callback %q", label, got, pcrCallback)
	}
	q := out.loc.Query()
	if got := q.Get("error"); got != "invalid_request" {
		f.t.Errorf("%s: error=%q want invalid_request", label, got)
	}
	if got := q.Get("error_description"); got != desc {
		f.t.Errorf("%s: error_description=%q want %q", label, got, desc)
	}
	if got := q.Get("state"); got != pcrState {
		f.t.Errorf("%s: state=%q want %q", label, got, pcrState)
	}
	if got := q.Get("code"); got != "" {
		f.t.Errorf("%s: code=%q want none", label, got)
	}
}

// requireRegistered asserts claims belong to the registration attempt that
// was submitted at submittedAt, and not to the session of sessionAuthTime
// (0 for none).
func requireRegistered(t *testing.T, claims map[string]any, submittedAt time.Time, sessionAuthTime int64) {
	t.Helper()
	if got, _ := claims["sub"].(string); got != pcrNewSubject {
		t.Errorf("id_token sub=%q want %q", got, pcrNewSubject)
	}
	at, _ := claims["auth_time"].(float64)
	if int64(at) != submittedAt.Unix() {
		t.Errorf("id_token auth_time=%d want %d (the registration submission)", int64(at), submittedAt.Unix())
	}
	if sessionAuthTime != 0 && int64(at) == sessionAuthTime {
		t.Errorf("id_token auth_time=%d equals the existing session's", int64(at))
	}
	if got, want := pcrStrings(claims["amr"]), []string{"otp"}; !reflect.DeepEqual(got, want) {
		t.Errorf("id_token amr=%v want %v (the Registration authenticator's AMR)", got, want)
	}
}

func pcrStrings(v any) []string {
	raw, _ := v.([]any)
	out := make([]string, 0, len(raw))
	for _, e := range raw {
		s, _ := e.(string)
		out = append(out, s)
	}
	return out
}

// TestScenario_PCR_001_RegistrationRunsInsteadOfPrimary checks that
// prompt=create without a session starts at the Registration step, never
// calls Primary, hands Registration no subject, and issues a code whose
// id_token names the new subject with the registration's auth_time and amr.
//
// Spec: Prompt Create 1.0 §4.1.
func TestScenario_PCR_001_RegistrationRunsInsteadOfPrimary(t *testing.T) {
	t.Parallel()
	f := newPCRFixture(t, true, false)

	out := f.authorize(pcrAuthz{route: pcrPlain, prompt: interaction.PromptCreate})
	if out.loc == nil || out.loc.Query().Get("code") != "" {
		t.Fatalf("prompt=create produced no interaction: %+v", out)
	}
	w := f.walk(out.loc, pcrAnswers())
	if want := []string{pcrRegisterPrompt, pcrConsentPrompt}; !reflect.DeepEqual(w.seen, want) {
		t.Fatalf("prompts shown=%v want %v", w.seen, want)
	}
	requireRegistered(t, f.exchange(out.pkce, w.redirect), w.submittedAt, 0)

	if got := f.primary.begins.Load(); got != 0 {
		t.Errorf("Primary.Begin called %d times, want 0", got)
	}
	if got := f.register.begins.Load(); got != 1 {
		t.Errorf("Registration.Begin called %d times, want 1", got)
	}
	if got := f.register.beginSubject.Load(); got == nil || *got != "" {
		t.Errorf("Registration BeginInput.Subject=%v want empty", got)
	}
}

// TestScenario_PCR_002_RuleSeesRegistrationKind checks that a RuleWhen
// predicate reading LoginContext.CompletedSteps sees the Registration kind
// and schedules an extra step, and that an ordinary login does not.
//
// Spec: Prompt Create 1.0 §4.1 (registration is an authentication step).
func TestScenario_PCR_002_RuleSeesRegistrationKind(t *testing.T) {
	t.Parallel()

	t.Run("registration", func(t *testing.T) {
		t.Parallel()
		f := newPCRFixture(t, true, true)
		out := f.authorize(pcrAuthz{route: pcrPlain, prompt: interaction.PromptCreate})
		w := f.walk(out.loc, pcrAnswers())
		if want := []string{pcrRegisterPrompt, pcrWelcomePrompt, pcrConsentPrompt}; !reflect.DeepEqual(w.seen, want) {
			t.Fatalf("prompts shown=%v want %v", w.seen, want)
		}
		if got := f.exchange(out.pkce, w.redirect)["sub"]; got != pcrNewSubject {
			t.Errorf("id_token sub=%v want %q", got, pcrNewSubject)
		}
		if got := f.welcome.begins.Load(); got != 1 {
			t.Errorf("welcome step ran %d times, want 1", got)
		}
	})

	t.Run("login", func(t *testing.T) {
		t.Parallel()
		f := newPCRFixture(t, true, true)
		out := f.authorize(pcrAuthz{route: pcrPlain})
		w := f.walk(out.loc, pcrAnswers())
		if want := []string{testkit.SubjectPromptType, pcrConsentPrompt}; !reflect.DeepEqual(w.seen, want) {
			t.Fatalf("prompts shown=%v want %v", w.seen, want)
		}
		if got := f.welcome.begins.Load(); got != 0 {
			t.Errorf("welcome step ran %d times on a login, want 0", got)
		}
	})
}

// TestScenario_PCR_003_LiveSessionAndGrantDoNotCarryOver checks that with a
// live session whose subject holds a grant covering the request,
// prompt=create still runs Registration with no inherited subject, shows
// consent for the new subject, and the id_token carries the new subject's
// attempt (sub, auth_time, amr) rather than the session's. A later request
// without prompt is then served from the new session.
//
// Spec: Prompt Create 1.0 §4.1.
func TestScenario_PCR_003_LiveSessionAndGrantDoNotCarryOver(t *testing.T) {
	t.Parallel()
	f := newPCRFixture(t, true, false)
	sessionAuthTime := f.login()

	// Control: the session and its grant serve the request silently.
	ctl := f.authorize(pcrAuthz{route: pcrPlain})
	if ctl.loc == nil || ctl.loc.Query().Get("code") == "" {
		t.Fatalf("control request was not served from the session: %+v", ctl)
	}
	if got := f.exchange(ctl.pkce, ctl.loc)["sub"]; got != pcrLoginSubject {
		t.Fatalf("control sub=%v want %q", got, pcrLoginSubject)
	}

	f.clock.Advance(30 * time.Minute)
	out := f.authorize(pcrAuthz{route: pcrPlain, prompt: interaction.PromptCreate})
	if out.loc == nil || out.loc.Query().Get("code") != "" {
		t.Fatalf("prompt=create was served from the session: %+v", out)
	}
	w := f.walk(out.loc, pcrAnswers())
	if want := []string{pcrRegisterPrompt, pcrConsentPrompt}; !reflect.DeepEqual(w.seen, want) {
		t.Fatalf("prompts shown=%v want %v (consent must be asked for the new subject)", w.seen, want)
	}
	requireRegistered(t, f.exchange(out.pkce, w.redirect), w.submittedAt, sessionAuthTime)
	if got := f.register.beginSubject.Load(); got == nil || *got != "" {
		t.Errorf("Registration BeginInput.Subject=%v want empty despite a live session for %q", got, pcrLoginSubject)
	}
	if got := f.primary.begins.Load(); got != 1 {
		t.Errorf("Primary.Begin called %d times, want 1 (the initial login only)", got)
	}

	// The registration replaced the browser's session subject.
	next := f.authorize(pcrAuthz{route: pcrPlain})
	if next.loc == nil || next.loc.Query().Get("code") == "" {
		t.Fatalf("request after registration was not served from the new session: %+v", next)
	}
	if got := f.exchange(next.pkce, next.loc)["sub"]; got != pcrNewSubject {
		t.Errorf("sub after registration=%v want %q", got, pcrNewSubject)
	}
}

// TestScenario_PCR_004_UnconfiguredRefusesCreate checks that an OP without
// LoginFlow.Registration refuses prompt=create with invalid_request and the
// fixed description, redirected to the RP with state echoed, and that an
// upper-case CREATE is refused the same way even with Registration set.
//
// Spec: Prompt Create 1.0 §4.1 / OIDC Core §3.1.2.6.
func TestScenario_PCR_004_UnconfiguredRefusesCreate(t *testing.T) {
	t.Parallel()

	t.Run("unconfigured", func(t *testing.T) {
		t.Parallel()
		f := newPCRFixture(t, false, false)
		out := f.authorize(pcrAuthz{route: pcrPlain, prompt: interaction.PromptCreate})
		f.requireRPError("create/unconfigured", pcrPlain, out, pcrDescUnrecognised)
	})

	t.Run("uppercase", func(t *testing.T) {
		t.Parallel()
		f := newPCRFixture(t, true, false)
		out := f.authorize(pcrAuthz{route: pcrPlain, prompt: "CREATE"})
		f.requireRPError("CREATE/configured", pcrPlain, out, pcrDescUnrecognised)
	})
}

// TestScenario_PCR_005_CreateCombinationRefused checks that, with
// Registration configured, create combined with another prompt value is
// refused (none keeps its own conflict description), that a repeated create
// is accepted as create, and that a tab separator makes the value unknown.
//
// Spec: Prompt Create 1.0 §4.1 / OIDC Core §3.1.2.1.
func TestScenario_PCR_005_CreateCombinationRefused(t *testing.T) {
	t.Parallel()
	f := newPCRFixture(t, true, false)

	refused := []struct {
		prompt string
		desc   string
	}{
		{"create login", pcrDescCreateConflict},
		{"login create", pcrDescCreateConflict},
		{"create consent", pcrDescCreateConflict},
		{"select_account create", pcrDescCreateConflict},
		{"create none", pcrDescNoneConflict},
		{"none create", pcrDescNoneConflict},
		{"create\tlogin", pcrDescUnrecognised},
	}
	for _, tc := range refused {
		out := f.authorize(pcrAuthz{route: pcrPlain, prompt: tc.prompt})
		f.requireRPError(fmt.Sprintf("prompt=%q", tc.prompt), pcrPlain, out, tc.desc)
	}

	out := f.authorize(pcrAuthz{route: pcrPlain, prompt: "create create"})
	if out.loc == nil {
		t.Fatalf("prompt=%q was refused: %+v", "create create", out)
	}
	w := f.walk(out.loc, pcrAnswers())
	if want := []string{pcrRegisterPrompt, pcrConsentPrompt}; !reflect.DeepEqual(w.seen, want) {
		t.Errorf("prompt=\"create create\" prompts=%v want %v", w.seen, want)
	}
	if got := f.exchange(out.pkce, w.redirect)["sub"]; got != pcrNewSubject {
		t.Errorf("prompt=\"create create\" sub=%v want %q", got, pcrNewSubject)
	}
}

// TestScenario_PCR_006_PARCarriesCreate checks that a pushed request is
// judged by the same rules: create is accepted and, redeemed at /authorize,
// runs Registration; it is refused at /par when Registration is not
// configured; and a pushed combination is refused at /par.
//
// Spec: RFC 9126 §2.1 / Prompt Create 1.0 §4.1.
func TestScenario_PCR_006_PARCarriesCreate(t *testing.T) {
	t.Parallel()

	t.Run("configured", func(t *testing.T) {
		t.Parallel()
		f := newPCRFixture(t, true, false)
		out := f.authorize(pcrAuthz{route: pcrPAR, prompt: interaction.PromptCreate})
		if out.status != http.StatusFound || out.loc == nil {
			t.Fatalf("PAR create: /authorize status=%d body=%v", out.status, out.body)
		}
		w := f.walk(out.loc, pcrAnswers())
		if want := []string{pcrRegisterPrompt, pcrConsentPrompt}; !reflect.DeepEqual(w.seen, want) {
			t.Fatalf("prompts shown=%v want %v", w.seen, want)
		}
		requireRegistered(t, f.exchange(out.pkce, w.redirect), w.submittedAt, 0)
	})

	t.Run("unconfigured", func(t *testing.T) {
		t.Parallel()
		f := newPCRFixture(t, false, false)
		out := f.authorize(pcrAuthz{route: pcrPAR, prompt: interaction.PromptCreate})
		f.requireRPError("PAR create/unconfigured", pcrPAR, out, pcrDescUnrecognised)
	})

	t.Run("combined", func(t *testing.T) {
		t.Parallel()
		f := newPCRFixture(t, true, false)
		out := f.authorize(pcrAuthz{route: pcrPAR, prompt: "create login"})
		f.requireRPError("PAR create login", pcrPAR, out, pcrDescCreateConflict)
	})
}

// TestScenario_PCR_007_JARClaimCarriesCreate checks that a prompt claim in
// a signed request object is judged by the same rules: a string claim runs
// Registration, an array claim is joined with spaces (so create plus another
// value is refused), and an OP without Registration refuses create.
//
// Spec: RFC 9101 §4 / Prompt Create 1.0 §4.1.
func TestScenario_PCR_007_JARClaimCarriesCreate(t *testing.T) {
	t.Parallel()

	t.Run("string", func(t *testing.T) {
		t.Parallel()
		f := newPCRFixture(t, true, false)
		out := f.authorize(pcrAuthz{route: pcrJAR, prompt: interaction.PromptCreate})
		if out.loc == nil {
			t.Fatalf("JAR create: /authorize status=%d body=%v", out.status, out.body)
		}
		w := f.walk(out.loc, pcrAnswers())
		if want := []string{pcrRegisterPrompt, pcrConsentPrompt}; !reflect.DeepEqual(w.seen, want) {
			t.Fatalf("prompts shown=%v want %v", w.seen, want)
		}
		requireRegistered(t, f.exchange(out.pkce, w.redirect), w.submittedAt, 0)
	})

	t.Run("array", func(t *testing.T) {
		t.Parallel()
		f := newPCRFixture(t, true, false)
		out := f.authorize(pcrAuthz{route: pcrJAR, promptArray: []string{"create", "login"}})
		f.requireRPError("JAR [create login]", pcrJAR, out, pcrDescCreateConflict)
	})

	t.Run("unconfigured", func(t *testing.T) {
		t.Parallel()
		f := newPCRFixture(t, false, false)
		out := f.authorize(pcrAuthz{route: pcrJAR, prompt: interaction.PromptCreate})
		f.requireRPError("JAR create/unconfigured", pcrJAR, out, pcrDescUnrecognised)
	})
}

// TestScenario_PCR_008_DiscoveryAdvertisesPromptValues checks that
// prompt_values_supported is the four core values, in that order, and gains
// create exactly when LoginFlow.Registration is set; and that an embedder
// cannot inject the member through DiscoveryMetadata.Extra.
//
// Spec: Prompt Create 1.0 §4.2.
func TestScenario_PCR_008_DiscoveryAdvertisesPromptValues(t *testing.T) {
	t.Parallel()
	core := []any{"none", "login", "consent", "select_account"}

	t.Run("configured", func(t *testing.T) {
		t.Parallel()
		f := newPCRFixture(t, true, false)
		_, _, doc := fetchDiscovery(t, f.tk.Server.URL)
		if want := append(slices.Clone(core), "create"); !reflect.DeepEqual(doc["prompt_values_supported"], want) {
			t.Errorf("prompt_values_supported=%v want %v", doc["prompt_values_supported"], want)
		}
	})

	t.Run("unconfigured", func(t *testing.T) {
		t.Parallel()
		f := newPCRFixture(t, false, false)
		_, _, doc := fetchDiscovery(t, f.tk.Server.URL)
		if !reflect.DeepEqual(doc["prompt_values_supported"], core) {
			t.Errorf("prompt_values_supported=%v want %v", doc["prompt_values_supported"], core)
		}
	})

	t.Run("extra_refused", func(t *testing.T) {
		t.Parallel()
		_, err := op.New(testkit.MinimalOptions(t, op.WithDiscoveryMetadata(op.DiscoveryMetadata{
			Extra: map[string]any{"prompt_values_supported": []string{"create"}},
		}))...)
		if err == nil {
			t.Fatal("op.New accepted Extra[prompt_values_supported]")
		}
		var typed *op.Error
		if !errors.As(err, &typed) {
			t.Fatalf("err=%v want *op.Error", err)
		}
		if !strings.Contains(err.Error(), "prompt_values_supported") {
			t.Errorf("err=%v does not name prompt_values_supported", err)
		}
	})
}

// TestScenario_PCR_009_RegistrationShapeRefused checks that op.New refuses a
// Registration that is not an ExternalStep, is a StepOneOf, counts failures,
// reuses another step's kind, or is named by a Rule — and accepts the valid
// shape.
//
// Spec: implementation contract (LoginFlow.Registration).
func TestScenario_PCR_009_RegistrationShapeRefused(t *testing.T) {
	t.Parallel()
	users := newPCRUserSink()
	clock := newPCRClock()
	valid := func() op.LoginFlow {
		flow, _, _ := pcrFlow(clock, users, true, nil)
		return flow
	}
	registerStep := func() op.ExternalStep {
		_, _, reg := pcrFlow(clock, users, true, nil)
		return op.ExternalStep{Authenticator: reg, KindLabel: pcrKindRegister}
	}

	// want names the rule each refused shape trips, so a row fails when its
	// own rule is removed rather than passing on an unrelated refusal.
	cases := []struct {
		name   string
		mutate func(*op.LoginFlow)
		want   string
	}{
		{"valid", func(*op.LoginFlow) {}, ""},
		{"built_in_step", func(f *op.LoginFlow) {
			f.Registration = op.PrimaryPassword{Store: inmem.New().UserPasswords()}
		}, "Registration must be an ExternalStep"},
		{"one_of", func(f *op.LoginFlow) {
			f.Registration = op.StepOneOf{Steps: []op.Step{registerStep()}}
		}, "Registration must be an ExternalStep"},
		{"count_failures", func(f *op.LoginFlow) {
			s := registerStep()
			s.CountFailures = true
			f.Registration = s
		}, "ExternalStep.CountFailures"},
		{"kind_reuses_primary", func(f *op.LoginFlow) {
			s := registerStep()
			s.KindLabel = op.StepKind("test.primary")
			f.Registration = s
		}, "is already used by Primary"},
		{"rule_names_registration", func(f *op.LoginFlow) {
			f.Rules = []op.Rule{op.RuleAlways(registerStep())}
		}, "must not name the Registration StepKind"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			flow := valid()
			tc.mutate(&flow)
			_, err := op.New(testkit.MinimalOptions(t, op.WithLoginFlow(flow))...)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("op.New refused the valid shape: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("op.New accepted the invalid Registration")
			}
			var typed *op.Error
			if !errors.As(err, &typed) {
				t.Errorf("err=%v want *op.Error", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err=%v, want the rule naming %q", err, tc.want)
			}
		})
	}
}

// pcrRow is one row of the pairwise matrix: a factor combination.
type pcrRow struct {
	registration bool
	prompt       string
	route        pcrRoute
	session      pcrSession
}

type pcrSession int

const (
	pcrNoSession pcrSession = iota
	pcrSessionOnly
	pcrSessionWithGrant
)

func (s pcrSession) String() string { return [...]string{"no_session", "session", "session_grant"}[s] }

// pcrMatrix covers every pair of factor levels across Registration x prompt
// x route x session in 15 rows.
var pcrMatrix = []pcrRow{
	{true, "create", pcrPlain, pcrNoSession},
	{true, "create", pcrPAR, pcrSessionOnly},
	{false, "create", pcrJAR, pcrSessionWithGrant},
	{false, "create login", pcrPlain, pcrSessionOnly},
	{true, "create login", pcrPAR, pcrSessionWithGrant},
	{true, "create login", pcrJAR, pcrNoSession},
	{true, "create none", pcrPlain, pcrSessionWithGrant},
	{false, "create none", pcrPAR, pcrNoSession},
	{true, "create none", pcrJAR, pcrSessionOnly},
	{false, "login", pcrPlain, pcrNoSession},
	{true, "login", pcrPAR, pcrSessionOnly},
	{false, "login", pcrJAR, pcrSessionWithGrant},
	{true, "", pcrPlain, pcrSessionOnly},
	{false, "", pcrPAR, pcrSessionWithGrant},
	{true, "", pcrJAR, pcrNoSession},
}

// TestScenario_PCR_010_PairwiseMatrixCoversAllPairs checks the matrix itself:
// every pair of levels of any two factors appears in at least one row.
func TestScenario_PCR_010_PairwiseMatrixCoversAllPairs(t *testing.T) {
	t.Parallel()
	levels := [][]string{
		{"on", "off"},
		{"create", "create login", "create none", "login", ""},
		{"plain", "par", "jar"},
		{"no_session", "session", "session_grant"},
	}
	reg := map[bool]string{true: "on", false: "off"}
	covered := map[string]bool{}
	for _, r := range pcrMatrix {
		v := []string{reg[r.registration], r.prompt, r.route.String(), r.session.String()}
		for i := range v {
			for j := i + 1; j < len(v); j++ {
				covered[fmt.Sprintf("%d=%s|%d=%s", i, v[i], j, v[j])] = true
			}
		}
	}
	want := 0
	for i := range levels {
		for j := i + 1; j < len(levels); j++ {
			for _, a := range levels[i] {
				for _, b := range levels[j] {
					want++
					if key := fmt.Sprintf("%d=%s|%d=%s", i, a, j, b); !covered[key] {
						t.Errorf("pair not covered: %s", key)
					}
				}
			}
		}
	}
	if want != 61 || len(covered) != want {
		t.Errorf("pairs: required=%d covered=%d, want 61 each", want, len(covered))
	}
}

// TestScenario_PCR_011_PairwiseOutcomes drives every matrix row and checks
// the outcome the factor combination determines: the refusal text (and
// where it surfaces), or the prompts shown, the subject, amr and the number
// of Primary and Registration invocations.
//
// Spec: Prompt Create 1.0 §4.1 / OIDC Core §3.1.2.1.
func TestScenario_PCR_011_PairwiseOutcomes(t *testing.T) {
	t.Parallel()
	for _, row := range pcrMatrix {
		name := fmt.Sprintf("reg_%t/prompt_%s/%s/%s", row.registration, strings.ReplaceAll(row.prompt, " ", "+"), row.route, row.session)
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			runPCRRow(t, row)
		})
	}
}

func runPCRRow(t *testing.T, row pcrRow) {
	t.Helper()
	f := newPCRFixture(t, row.registration, false)
	if row.session != pcrNoSession {
		f.login()
	}
	primaryBefore := f.primary.begins.Load()

	// A grant for "openid" exists only in the session_grant rows' sense of
	// covering the request: the others ask for a scope the grant lacks.
	scope := "openid profile"
	if row.session == pcrSessionWithGrant {
		scope = "openid"
	}
	out := f.authorize(pcrAuthz{route: row.route, prompt: row.prompt, scope: scope})

	toks := strings.Fields(row.prompt)
	hasCreate := slices.Contains(toks, "create")
	switch {
	case hasCreate && !row.registration:
		f.requireRPError(t.Name(), row.route, out, pcrDescUnrecognised)
		return
	case hasCreate && len(toks) > 1:
		desc := pcrDescCreateConflict
		if slices.Contains(toks, "none") {
			desc = pcrDescNoneConflict
		}
		f.requireRPError(t.Name(), row.route, out, desc)
		return
	}

	if out.loc == nil {
		t.Fatalf("/authorize status=%d body=%v, want a redirect", out.status, out.body)
	}
	w := f.walk(out.loc, pcrAnswers())
	claims := f.exchange(out.pkce, w.redirect)
	primaryCalls := f.primary.begins.Load() - primaryBefore

	if hasCreate {
		if want := []string{pcrRegisterPrompt, pcrConsentPrompt}; !reflect.DeepEqual(w.seen, want) {
			t.Errorf("prompts shown=%v want %v", w.seen, want)
		}
		requireRegistered(t, claims, w.submittedAt, 0)
		if primaryCalls != 0 || f.register.begins.Load() != 1 {
			t.Errorf("Primary calls=%d Registration calls=%d, want 0 and 1", primaryCalls, f.register.begins.Load())
		}
		return
	}

	// Ordinary login: the prompts follow from the session and the grant.
	var want []string
	wantPrimary := int32(0)
	switch {
	case row.prompt == "login":
		want, wantPrimary = []string{testkit.SubjectPromptType}, 1
		if row.session != pcrSessionWithGrant {
			want = append(want, pcrConsentPrompt)
		}
	case row.session == pcrNoSession:
		want, wantPrimary = []string{testkit.SubjectPromptType, pcrConsentPrompt}, 1
	case row.session == pcrSessionOnly:
		want = []string{pcrConsentPrompt}
	}
	if !slices.Equal(w.seen, want) {
		t.Errorf("prompts shown=%v want %v", w.seen, want)
	}
	if got, _ := claims["sub"].(string); got != pcrLoginSubject {
		t.Errorf("id_token sub=%q want %q", got, pcrLoginSubject)
	}
	if got, want := pcrStrings(claims["amr"]), []string{"pwd"}; !reflect.DeepEqual(got, want) {
		t.Errorf("id_token amr=%v want %v", got, want)
	}
	if primaryCalls != wantPrimary || f.register.begins.Load() != 0 {
		t.Errorf("Primary calls=%d Registration calls=%d, want %d and 0", primaryCalls, f.register.begins.Load(), wantPrimary)
	}
}
