package scenarios_test

// Catalog: test/scenarios/catalog/first_party.yaml (FPC-NNN)
// Spec:
//   - OIDC Core 1.0 §3.1.2.4 — consent
//   - OIDC Core 1.0 §3.1.2.1 — prompt
//   - W3C Fetch Metadata Request Headers — Sec-Fetch-Site
//   - OP design — op.WithFirstPartyClients

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/profile"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

const (
	fpcClientID      = "fpc-app"
	fpcOtherClientID = "fpc-partner"
	fpcCallback      = "https://app.testkit.invalid/callback"
	fpcOtherCallback = "https://partner.testkit.invalid/callback"
	fpcState         = "fpc-state"

	fpcConsentPrompt  = "consent.scope"
	fpcRegisterPrompt = "auth.test.fpc.register"
	fpcRegisterField  = "new_subject"
	fpcAuditEvent     = "consent.granted.first_party"
)

// fpcRegistrar is the embedder's account-creation step: it binds the
// subject the submission names.
type fpcRegistrar struct{}

func (fpcRegistrar) Type() op.FactorType { return "test.fpc.register" }
func (fpcRegistrar) AAL() op.AAL         { return op.AAL1 }
func (fpcRegistrar) AMR() string         { return "otp" }
func (fpcRegistrar) Prompts() []string   { return []string{fpcRegisterPrompt} }

func (fpcRegistrar) Begin(context.Context, op.BeginInput) (interaction.Step, error) {
	return interaction.Step{Prompt: &interaction.Prompt{
		Type: fpcRegisterPrompt,
		Inputs: []interaction.FieldSpec{{
			Name: fpcRegisterField, Kind: interaction.FieldText, Required: true, MinLen: 1, MaxLen: 256,
		}},
	}}, nil
}

func (fpcRegistrar) Continue(_ context.Context, in op.ContinueInput) (interaction.Step, error) {
	sub := in.Submission.Values[fpcRegisterField]
	if sub == "" {
		return interaction.Step{}, testkit.ErrSubjectMissing
	}
	return interaction.Step{Result: &interaction.Result{Subject: sub, AuthTime: in.AuthTime}}, nil
}

type fpcFixture struct {
	t     *testing.T
	tk    *testkit.Provider
	audit *scenariokit.AuditCapture
	cl    *http.Client
}

// newFPCFixture builds an OP with two static public clients, only the
// first of which is first-party, over the testkit's subject-echo login.
func newFPCFixture(t *testing.T, withRegistration bool) *fpcFixture {
	t.Helper()
	capture := scenariokit.NewAuditCapture()
	opts := []op.Option{
		op.WithAuditLogger(capture.Logger()),
		op.WithStaticClients(
			op.PublicClient{
				ID: fpcClientID, RedirectURIs: []string{fpcCallback},
				Scopes: []string{"openid", "profile", "offline_access"},
			},
			op.PublicClient{
				ID: fpcOtherClientID, RedirectURIs: []string{fpcOtherCallback},
				Scopes: []string{"openid", "profile"},
			},
		),
		op.WithFirstPartyClients(fpcClientID),
	}
	if withRegistration {
		opts = append(opts, op.WithLoginFlow(op.LoginFlow{
			Primary:      op.ExternalStep{Authenticator: testkit.SubjectAuthenticator{}, KindLabel: "test.fpc.primary"},
			Registration: op.ExternalStep{Authenticator: fpcRegistrar{}, KindLabel: "test.fpc.register"},
		}))
	}
	tk := testkit.NewProvider(t, testkit.WithOptions(opts...))
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	return &fpcFixture{t: t, tk: tk, audit: capture, cl: tk.HTTPClient(jar)}
}

// fpcRequest describes one /authorize navigation.
type fpcRequest struct {
	clientID string
	redirect string
	scope    string
	prompt   string
	// fetchSite is sent as Sec-Fetch-Site; empty omits the header.
	fetchSite string
	// subject is what the sign-in (or registration) prompt is answered with.
	subject string
}

// fpcWalk is what one navigation observed.
type fpcWalk struct {
	redirect *url.URL
	// seen lists the prompt types shown, in order.
	seen []string
}

func (w fpcWalk) sawConsent() bool {
	for _, p := range w.seen {
		if p == fpcConsentPrompt {
			return true
		}
	}
	return false
}

// run navigates to /authorize and answers every prompt: the sign-in or
// registration prompt with r.subject, and a consent prompt (if one is
// shown) with an approval so the walk always terminates at the RP.
func (f *fpcFixture) run(r fpcRequest) fpcWalk {
	f.t.Helper()
	if r.clientID == "" {
		r.clientID = fpcClientID
	}
	if r.redirect == "" {
		r.redirect = fpcCallback
	}
	params := scenariokit.AuthorizeParams{
		ClientID: r.clientID, RedirectURI: r.redirect, Scope: r.scope, State: fpcState,
	}.Values()
	if r.prompt != "" {
		params.Set("prompt", r.prompt)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		f.tk.Server.URL+"/oidc/auth?"+params.Encode(), http.NoBody)
	if err != nil {
		f.t.Fatalf("build /authorize: %v", err)
	}
	if r.fetchSite != "" {
		req.Header.Set("Sec-Fetch-Site", r.fetchSite)
	}
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Dest", "document")
	resp, err := f.cl.Do(req)
	if err != nil {
		f.t.Fatalf("GET /authorize: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		f.t.Fatalf("/authorize status=%d body=%s", resp.StatusCode, body)
	}
	loc, err := resp.Location()
	if err != nil {
		f.t.Fatalf("/authorize Location: %v", err)
	}
	return f.walk(loc, r)
}

func (f *fpcFixture) walk(loc *url.URL, r fpcRequest) fpcWalk {
	f.t.Helper()
	var w fpcWalk
	if !strings.HasPrefix(loc.Path, "/oidc/interaction/") {
		w.redirect = loc
		return w
	}
	path := loc.Path
	resp := f.get(f.tk.Server.URL + path)
	var csrf string
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
		switch typ {
		case fpcConsentPrompt:
			resp = testkit.PostConsentApproval(f.t, f.cl, f.tk.Server.URL+path, f.tk.Issuer,
				csrf, stateRef, testkit.ApprovedScopesFrom(f.t, env))
		case testkit.SubjectPromptType:
			resp = f.submit(path, csrf, stateRef, map[string]string{testkit.SubjectFieldName: r.subject})
		case fpcRegisterPrompt:
			resp = f.submit(path, csrf, stateRef, map[string]string{fpcRegisterField: r.subject})
		default:
			f.t.Fatalf("unexpected prompt %q (seen %v)", typ, w.seen)
		}
	}
	f.t.Fatalf("interaction did not terminate (seen %v)", w.seen)
	return w
}

func (f *fpcFixture) get(rawURL string) *http.Response {
	f.t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, rawURL, http.NoBody)
	if err != nil {
		f.t.Fatalf("build GET %s: %v", rawURL, err)
	}
	resp, err := f.cl.Do(req)
	if err != nil {
		f.t.Fatalf("GET %s: %v", rawURL, err)
	}
	return resp
}

func (f *fpcFixture) submit(path, csrf, stateRef string, values map[string]string) *http.Response {
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

// requireCode fails unless w ended at wantCallback carrying a code.
func (f *fpcFixture) requireCode(w fpcWalk, wantCallback string) {
	f.t.Helper()
	if w.redirect == nil {
		f.t.Fatalf("walk did not reach the RP (seen %v)", w.seen)
	}
	got := w.redirect.Scheme + "://" + w.redirect.Host + w.redirect.Path
	if got != wantCallback || w.redirect.Query().Get("code") == "" {
		f.t.Fatalf("RP redirect = %s, want a code at %s", w.redirect, wantCallback)
	}
}

// firstPartyAudits returns the auto-grant audit events for clientID.
func (f *fpcFixture) firstPartyAudits(clientID string) []scenariokit.AuditEvent {
	f.t.Helper()
	var out []scenariokit.AuditEvent
	for _, ev := range f.audit.EventsByName(fpcAuditEvent) {
		if attrString(ev, "client_id") == clientID {
			out = append(out, ev)
		}
	}
	return out
}

func attrString(ev scenariokit.AuditEvent, key string) string {
	for _, a := range ev.Attrs {
		if a.Key == key {
			return a.Value.String()
		}
	}
	return ""
}

// TestScenario_FPC_001_FreshLoginSkipsConsentAndBindsSignedInSubject checks
// that a first-party client with no session signs in, skips the consent
// prompt, and gets a grant for the subject that sign-in bound.
//
// Spec: OP design (first-party auto-consent).
func TestScenario_FPC_001_FreshLoginSkipsConsentAndBindsSignedInSubject(t *testing.T) {
	t.Parallel()

	f := newFPCFixture(t, false)
	const subject = "fpc-user-fresh"
	w := f.run(fpcRequest{scope: "openid profile", fetchSite: "same-origin", subject: subject})

	if w.sawConsent() {
		t.Fatalf("consent prompt shown to a first-party client (seen %v)", w.seen)
	}
	f.requireCode(w, fpcCallback)

	g, err := f.tk.Store.Grants().FindBySubjectClient(context.Background(), subject, fpcClientID)
	if err != nil {
		t.Fatalf("grant for (%s, %s): %v", subject, fpcClientID, err)
	}
	if g.Subject != subject || g.ClientID != fpcClientID {
		t.Errorf("grant = (%s, %s), want (%s, %s)", g.Subject, g.ClientID, subject, fpcClientID)
	}
	for _, want := range []string{"openid", "profile"} {
		found := false
		for _, s := range g.Scope {
			found = found || s == want
		}
		if !found {
			t.Errorf("grant scope %v missing %q", g.Scope, want)
		}
	}
	if n := len(f.firstPartyAudits(fpcClientID)); n != 1 {
		t.Errorf("%s events for %s = %d, want 1", fpcAuditEvent, fpcClientID, n)
	}
}

// TestScenario_FPC_002_PromptLoginWithSessionSkipsConsent checks that
// re-authentication over a live session still auto-grants.
//
// Spec: OP design (first-party auto-consent).
func TestScenario_FPC_002_PromptLoginWithSessionSkipsConsent(t *testing.T) {
	t.Parallel()

	f := newFPCFixture(t, false)
	const subject = "fpc-user-relogin"
	first := f.run(fpcRequest{scope: "openid", fetchSite: "same-origin", subject: subject})
	f.requireCode(first, fpcCallback)

	w := f.run(fpcRequest{scope: "openid", prompt: "login", fetchSite: "same-origin", subject: subject})
	if len(w.seen) == 0 || w.seen[0] != testkit.SubjectPromptType {
		t.Fatalf("prompt=login did not run the sign-in prompt (seen %v)", w.seen)
	}
	if w.sawConsent() {
		t.Fatalf("consent prompt shown after prompt=login (seen %v)", w.seen)
	}
	f.requireCode(w, fpcCallback)
	if _, err := f.tk.Store.Grants().FindBySubjectClient(context.Background(), subject, fpcClientID); err != nil {
		t.Errorf("grant for (%s, %s): %v", subject, fpcClientID, err)
	}
	if n := len(f.firstPartyAudits(fpcClientID)); n != 2 {
		t.Errorf("%s events = %d, want 2 (one per completed request)", fpcAuditEvent, n)
	}
}

// TestScenario_FPC_003_OfflineAccessStillPrompts checks that offline_access
// keeps the explicit consent ceremony after sign-in.
//
// Spec: OIDC Core 1.0 §11.
func TestScenario_FPC_003_OfflineAccessStillPrompts(t *testing.T) {
	t.Parallel()

	f := newFPCFixture(t, false)
	w := f.run(fpcRequest{scope: "openid offline_access", fetchSite: "same-origin", subject: "fpc-user-offline"})
	if !w.sawConsent() {
		t.Fatalf("offline_access skipped consent (seen %v)", w.seen)
	}
	if n := len(f.firstPartyAudits(fpcClientID)); n != 0 {
		t.Errorf("%s events = %d, want 0", fpcAuditEvent, n)
	}
}

// TestScenario_FPC_004_UntrustedFetchSiteStillPrompts checks that only a
// same-origin navigation skips consent.
//
// Spec: W3C Fetch Metadata Request Headers.
func TestScenario_FPC_004_UntrustedFetchSiteStillPrompts(t *testing.T) {
	t.Parallel()

	for _, site := range []string{"cross-site", "none", ""} {
		t.Run("sec-fetch-site="+site, func(t *testing.T) {
			t.Parallel()

			f := newFPCFixture(t, false)
			w := f.run(fpcRequest{scope: "openid", fetchSite: site, subject: "fpc-user-site"})
			if !w.sawConsent() {
				t.Fatalf("Sec-Fetch-Site %q skipped consent (seen %v)", site, w.seen)
			}
			if n := len(f.firstPartyAudits(fpcClientID)); n != 0 {
				t.Errorf("%s events = %d, want 0", fpcAuditEvent, n)
			}
		})
	}
}

// TestScenario_FPC_005_PromptConsentStillPrompts checks that the RP's
// explicit re-consent request wins over the first-party posture.
//
// Spec: OIDC Core 1.0 §3.1.2.1.
func TestScenario_FPC_005_PromptConsentStillPrompts(t *testing.T) {
	t.Parallel()

	f := newFPCFixture(t, false)
	w := f.run(fpcRequest{scope: "openid", prompt: "consent", fetchSite: "same-origin", subject: "fpc-user-consent"})
	if !w.sawConsent() {
		t.Fatalf("prompt=consent skipped consent (seen %v)", w.seen)
	}
	if n := len(f.firstPartyAudits(fpcClientID)); n != 0 {
		t.Errorf("%s events = %d, want 0", fpcAuditEvent, n)
	}
}

// TestScenario_FPC_006_PromptCreateStillPrompts checks that an account
// bound by registration sees the consent prompt.
//
// Spec: Prompt Create 1.0 §4.1.
func TestScenario_FPC_006_PromptCreateStillPrompts(t *testing.T) {
	t.Parallel()

	f := newFPCFixture(t, true)
	w := f.run(fpcRequest{scope: "openid", prompt: "create", fetchSite: "same-origin", subject: "fpc-user-new"})
	if len(w.seen) == 0 || w.seen[0] != fpcRegisterPrompt {
		t.Fatalf("prompt=create did not start at the registration step (seen %v)", w.seen)
	}
	if !w.sawConsent() {
		t.Fatalf("prompt=create skipped consent (seen %v)", w.seen)
	}
	if n := len(f.firstPartyAudits(fpcClientID)); n != 0 {
		t.Errorf("%s events = %d, want 0", fpcAuditEvent, n)
	}
}

// TestScenario_FPC_007_NonListedClientStillPrompts checks that the skip is
// per client: the unlisted client prompts, the listed one does not.
//
// Spec: OP design (first-party auto-consent).
func TestScenario_FPC_007_NonListedClientStillPrompts(t *testing.T) {
	t.Parallel()

	f := newFPCFixture(t, false)
	other := f.run(fpcRequest{
		clientID: fpcOtherClientID, redirect: fpcOtherCallback,
		scope: "openid", fetchSite: "same-origin", subject: "fpc-user-multi",
	})
	if !other.sawConsent() {
		t.Fatalf("unlisted client skipped consent (seen %v)", other.seen)
	}
	f.requireCode(other, fpcOtherCallback)
	if n := len(f.firstPartyAudits(fpcOtherClientID)); n != 0 {
		t.Errorf("%s events for the unlisted client = %d, want 0", fpcAuditEvent, n)
	}

	listed := f.run(fpcRequest{scope: "openid", fetchSite: "same-origin", subject: "fpc-user-multi"})
	if listed.sawConsent() {
		t.Fatalf("listed client was prompted (seen %v)", listed.seen)
	}
	f.requireCode(listed, fpcCallback)
}

// TestScenario_FPC_008_FAPI2RefusesFirstPartyClients checks the
// construction-time refusal under a FAPI 2.0 profile.
//
// Spec: FAPI 2.0 Security Profile.
func TestScenario_FPC_008_FAPI2RefusesFirstPartyClients(t *testing.T) {
	t.Parallel()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	jwks, err := json.Marshal(josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{{
		Key: &priv.PublicKey, KeyID: "fpc-kid", Algorithm: string(josev4.ES256), Use: "sig",
	}}})
	if err != nil {
		t.Fatalf("marshal JWKS: %v", err)
	}
	client := op.PrivateKeyJWTClient{
		ID: fpcClientID, JWKS: jwks, RedirectURIs: []string{fpcCallback}, Scopes: []string{"openid"},
	}
	base := []op.Option{
		op.WithProfile(profile.FAPI2Baseline),
		op.WithFeature(feature.DPoP),
		op.WithStaticClients(client),
	}

	// Control: the same options without the first-party list construct,
	// so the refusal below is attributable to WithFirstPartyClients.
	if _, err := op.New(testkit.MinimalOptions(t, base...)...); err != nil {
		t.Fatalf("control op.New without WithFirstPartyClients: %v", err)
	}

	_, err = op.New(testkit.MinimalOptions(t, append(base, op.WithFirstPartyClients(fpcClientID))...)...)
	if err == nil {
		t.Fatal("op.New accepted WithFirstPartyClients under a FAPI 2.0 profile")
	}
	if !strings.Contains(err.Error(), "FAPI 2.0") {
		t.Errorf("error %q does not name FAPI 2.0", err)
	}
}
