package op_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/interaction"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// dummyStep is a built-in [op.Step] value used as the [op.Rule.Then]
// payload in the rule helper tests. The tests only inspect
// [op.Rule.When]; the concrete Step is irrelevant beyond satisfying
// the interface. Using a built-in keeps the test file from declaring
// a throwaway interface implementation that mirrors the real one.
var dummyStep op.Step = op.StepCaptcha{}

// TestRuleAlways verifies [op.RuleAlways] matches every
// [op.LoginContext].
func TestRuleAlways(t *testing.T) {
	t.Parallel()
	r := op.RuleAlways(dummyStep)
	if r.Then == nil {
		t.Fatal("RuleAlways: Then should not be nil")
	}
	if !r.When(op.LoginContext{}) {
		t.Error("RuleAlways: empty LoginContext should match")
	}
	if !r.When(op.LoginContext{FailedAttempts: 99, RiskScore: op.RiskScoreHigh}) {
		t.Error("RuleAlways: populated LoginContext should match")
	}
}

// TestRuleAfterFailedAttempts pins the inclusive boundary at n.
func TestRuleAfterFailedAttempts(t *testing.T) {
	t.Parallel()
	r := op.RuleAfterFailedAttempts(3, dummyStep)
	cases := []struct {
		failed int
		match  bool
	}{
		{failed: 0, match: false},
		{failed: 2, match: false},
		{failed: 3, match: true},
		{failed: 4, match: true},
	}
	for _, tc := range cases {
		if got := r.When(op.LoginContext{FailedAttempts: tc.failed}); got != tc.match {
			t.Errorf("RuleAfterFailedAttempts(3): FailedAttempts=%d got=%v want=%v", tc.failed, got, tc.match)
		}
	}
}

// TestRuleRisk pins the inclusive threshold and confirms RiskScore
// ordering supports `>=` comparison.
func TestRuleRisk(t *testing.T) {
	t.Parallel()
	r := op.RuleRisk(op.RiskScoreMedium, dummyStep)
	cases := []struct {
		score op.RiskScore
		match bool
	}{
		{score: op.RiskScoreNone, match: false},
		{score: op.RiskScoreLow, match: false},
		{score: op.RiskScoreMedium, match: true},
		{score: op.RiskScoreHigh, match: true},
	}
	for _, tc := range cases {
		if got := r.When(op.LoginContext{RiskScore: tc.score}); got != tc.match {
			t.Errorf("RuleRisk(Medium): score=%v got=%v want=%v", tc.score, got, tc.match)
		}
	}
}

// TestRuleNewDevice covers the boolean predicate.
func TestRuleNewDevice(t *testing.T) {
	t.Parallel()
	r := op.RuleNewDevice(dummyStep)
	if r.When(op.LoginContext{NewDevice: false}) {
		t.Error("RuleNewDevice: NewDevice=false should not match")
	}
	if !r.When(op.LoginContext{NewDevice: true}) {
		t.Error("RuleNewDevice: NewDevice=true should match")
	}
}

// TestRuleClient covers the client_id equality predicate.
func TestRuleClient(t *testing.T) {
	t.Parallel()
	r := op.RuleClient("admin-portal", dummyStep)
	if !r.When(op.LoginContext{ClientID: "admin-portal"}) {
		t.Error("RuleClient: matching ClientID should match")
	}
	if r.When(op.LoginContext{ClientID: "shop-frontend"}) {
		t.Error("RuleClient: non-matching ClientID should not match")
	}
	if r.When(op.LoginContext{}) {
		t.Error("RuleClient: empty ClientID should not match")
	}
}

// TestRuleScope covers the case-sensitive scope-set membership.
func TestRuleScope(t *testing.T) {
	t.Parallel()
	r := op.RuleScope("write:billing", dummyStep)
	if !r.When(op.LoginContext{RequestedScopes: op.ScopeSet{
		op.ScopeName("openid"):        {},
		op.ScopeName("write:billing"): {},
	}}) {
		t.Error("RuleScope: scope present should match")
	}
	if r.When(op.LoginContext{RequestedScopes: op.ScopeSet{
		op.ScopeName("openid"):  {},
		op.ScopeName("profile"): {},
	}}) {
		t.Error("RuleScope: scope absent should not match")
	}
	if r.When(op.LoginContext{RequestedScopes: op.ScopeSet{
		op.ScopeName("WRITE:BILLING"): {},
	}}) {
		t.Error("RuleScope: case mismatch should not match (RFC 6749 §3.3 case-sensitive)")
	}
}

// TestRuleACR covers the acr_values list-membership predicate.
func TestRuleACR(t *testing.T) {
	t.Parallel()
	r := op.RuleACR("urn:mfa", dummyStep)
	if !r.When(op.LoginContext{ACRValues: []string{"urn:mfa"}}) {
		t.Error("RuleACR: acr present should match")
	}
	if !r.When(op.LoginContext{ACRValues: []string{"urn:loa1", "urn:mfa", "urn:loa3"}}) {
		t.Error("RuleACR: acr present in middle of list should match")
	}
	if r.When(op.LoginContext{ACRValues: []string{"urn:loa1"}}) {
		t.Error("RuleACR: acr absent should not match")
	}
	if r.When(op.LoginContext{}) {
		t.Error("RuleACR: empty ACRValues should not match")
	}
}

// TestRuleWhen covers the caller-supplied predicate path and the
// nil-predicate fallback, which matches the [op.Rule.When] contract
// that an absent predicate fires on every pass.
func TestRuleWhen(t *testing.T) {
	t.Parallel()
	called := 0
	r := op.RuleWhen(func(lc op.LoginContext) bool {
		called++
		return lc.FailedAttempts == 1
	}, dummyStep)
	if !r.When(op.LoginContext{FailedAttempts: 1}) {
		t.Error("RuleWhen: predicate should fire on FailedAttempts==1")
	}
	if r.When(op.LoginContext{FailedAttempts: 2}) {
		t.Error("RuleWhen: predicate should not fire on FailedAttempts==2")
	}
	if called != 2 {
		t.Errorf("RuleWhen: predicate called %d times, want 2", called)
	}

	// A nil predicate falls back to constant-true, so RuleWhen(nil, s)
	// and the bare struct literal op.Rule{Then: s} declare the same
	// rule. Constant-false would make the declared step unreachable
	// without saying so.
	rNil := op.RuleWhen(nil, dummyStep)
	if rNil.When == nil {
		t.Fatal("RuleWhen(nil): When should be set to a constant-true predicate, not nil")
	}
	if !rNil.When(op.LoginContext{}) {
		t.Error("RuleWhen(nil): predicate should be constant-true")
	}
	if !rNil.When(op.LoginContext{FailedAttempts: 99, NewDevice: true}) {
		t.Error("RuleWhen(nil): predicate should be constant-true on populated context")
	}
}

// promptRecorderDriver is an embedder [interaction.Driver] that records
// the type of every prompt the orchestrator emits. Recording the type is
// all the nil-predicate test needs: which step the flow reaches is the
// question, and the prompt type names it.
type promptRecorderDriver struct{ types []string }

func (d *promptRecorderDriver) Render(_ http.ResponseWriter, _ *http.Request, p interaction.Prompt) error {
	d.types = append(d.types, p.Type)
	return nil
}

func (d *promptRecorderDriver) ParseSubmission(*http.Request) (interaction.FormSubmission, error) {
	return interaction.FormSubmission{}, nil
}

// TestRuleNilWhenFiresInACompiledFlow pins the [op.Rule.When] contract
// where it decides whether a user is asked for a second factor: a rule
// written as a bare struct literal, with no predicate, fires.
//
// The rule's Then here is a captcha, which the orchestrator schedules
// ahead of the primary credential, so the very first prompt of the
// ceremony reports whether the predicate matched. Were an absent
// predicate read as "never fires", the flow would compile, construct,
// and then run the primary factor alone — the declared step silently
// dropped, with nothing on the wire to say so.
func TestRuleNilWhenFiresInACompiledFlow(t *testing.T) {
	t.Parallel()

	const clientID = "rule-nil-when-client"
	const redirectURI = "https://rp.example.com/cb"

	st := inmem.New()
	driver := &promptRecorderDriver{}
	provider, err := op.New(append(validBaseOptsWithStoreNoAuthn(t, st),
		op.WithLoginFlow(op.LoginFlow{
			Primary: op.PrimaryPassword{Store: st.UserPasswords()},
			// When is deliberately left unset: this is the struct-literal
			// spelling of RuleAlways.
			Rules: []op.Rule{{Then: op.StepCaptcha{Verifier: typedCaptchaVerifier{}}}},
		}),
		op.WithInteractionDriver(driver),
		op.WithStaticClients(op.PublicClient{
			ID:           clientID,
			RedirectURIs: []string{redirectURI},
			Scopes:       []string{"openid"},
		}),
	)...)
	if err != nil {
		t.Fatalf("op.New with a nil-When rule: %v", err)
	}

	verifier := strings.Repeat("v", 43)
	sum := sha256.Sum256([]byte(verifier))
	values := url.Values{
		"client_id":             {clientID},
		"response_type":         {"code"},
		"redirect_uri":          {redirectURI},
		"scope":                 {"openid"},
		"state":                 {"state-rule-nil-when"},
		"nonce":                 {"nonce-rule-nil-when"},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	authRec := httptest.NewRecorder()
	provider.ServeHTTP(authRec, httptest.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		validIssuer+"/oidc/auth?"+values.Encode(),
		http.NoBody,
	))
	authResp := authRec.Result()
	defer authResp.Body.Close()
	if authResp.StatusCode != http.StatusFound {
		raw, _ := io.ReadAll(authResp.Body)
		t.Fatalf("/authorize status = %d, want 302; body=%s", authResp.StatusCode, raw)
	}
	location, err := authResp.Location()
	if err != nil {
		t.Fatalf("/authorize Location: %v", err)
	}

	stepReq := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodGet,
		validIssuer+location.RequestURI(),
		http.NoBody,
	)
	for _, c := range authResp.Cookies() {
		stepReq.AddCookie(c)
	}
	stepRec := httptest.NewRecorder()
	provider.ServeHTTP(stepRec, stepReq)
	stepResp := stepRec.Result()
	defer stepResp.Body.Close()
	if stepResp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(stepResp.Body)
		t.Fatalf("/interaction status = %d, want 200; body=%s", stepResp.StatusCode, raw)
	}

	if len(driver.types) == 0 {
		t.Fatal("the ceremony emitted no prompt at all")
	}
	if got := driver.types[0]; got != "captcha" {
		t.Errorf("first prompt type = %q, want %q; a rule whose When is unset must fire, "+
			"not vanish and leave the primary factor standing alone", got, "captcha")
	}
}

// TestRuleThenPropagation pins that every helper preserves the
// caller-supplied [op.Step] verbatim.
func TestRuleThenPropagation(t *testing.T) {
	t.Parallel()
	step := op.StepTOTP{}
	rules := []op.Rule{
		op.RuleAlways(step),
		op.RuleAfterFailedAttempts(1, step),
		op.RuleRisk(op.RiskScoreLow, step),
		op.RuleNewDevice(step),
		op.RuleClient("c", step),
		op.RuleScope("s", step),
		op.RuleACR("a", step),
		op.RuleWhen(func(op.LoginContext) bool { return true }, step),
	}
	for i, r := range rules {
		if r.Then == nil {
			t.Errorf("rules[%d]: Then is nil", i)
			continue
		}
		if r.Then.Kind() != op.StepKindTOTP {
			t.Errorf("rules[%d]: Then.Kind=%q want %q", i, r.Then.Kind(), op.StepKindTOTP)
		}
	}
}
