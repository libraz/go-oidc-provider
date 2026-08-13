package scenarios_test

// Catalog: test/scenarios/catalog/backchannel_logout.yaml (BCL-NNN)
// Spec:
//   - OIDC Back-Channel Logout 1.0
//   - OIDC Core 1.0 §2, §3.1.3.6
//   - OIDC Discovery 1.0
//   - OIDC Front-Channel Logout 1.0 / Session Management 1.0
//   - RFC 8417, RFC 7519, RFC 7515

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"slices"
	"sort"
	"sync"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/testkit"
	"github.com/libraz/go-oidc-provider/test/scenarios/internal/scenariokit"
)

// bclSubject is the end user whose session the fan-out tests terminate.
const bclSubject = "user-bcl"

// bclStubRP is a relying party that records the Logout Tokens the OP
// POSTs to it. The recorded tokens are the only honest evidence that a
// delivery happened: the coordinator reports per-RP outcome through the
// audit stream and never through the /end_session response.
type bclStubRP struct {
	server *httptest.Server

	mu     sync.Mutex
	tokens []string
	status int
}

// newBCLStubRP starts a stub RP that answers every logout POST with
// status. Passing 0 selects 200.
func newBCLStubRP(t *testing.T, status int) *bclStubRP {
	t.Helper()
	if status == 0 {
		status = http.StatusOK
	}
	rp := &bclStubRP{status: status}
	rp.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err == nil {
			rp.mu.Lock()
			rp.tokens = append(rp.tokens, r.PostFormValue("logout_token"))
			rp.mu.Unlock()
		}
		w.WriteHeader(rp.status)
	}))
	t.Cleanup(rp.server.Close)
	return rp
}

// uri is the value registered as the client's backchannel_logout_uri.
func (r *bclStubRP) uri() string { return r.server.URL + "/backchannel-logout" }

// received returns the Logout Tokens this RP was handed.
func (r *bclStubRP) received() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.tokens)
}

// newBCLProvider stands up an OP whose deliverer may reach a loopback
// stub RP. The dev opt-in is the only configuration that admits a
// http://127.0.0.1 backchannel_logout_uri — at registration and at the
// SSRF gate alike — which is what makes the fan-out observable on the
// wire at all.
func newBCLProvider(t *testing.T, capture *scenariokit.AuditCapture) *testkit.Provider {
	t.Helper()
	return testkit.NewProvider(t, testkit.WithOptions(
		op.WithAllowInsecureBackchannelLogoutForDev(),
		op.WithAuditLogger(capture.Logger()),
	))
}

// newBCLBrowser returns a cookie-jarred client that stands in for one
// end user's browser across the whole scenario: the authorization flow
// establishes the OP session cookie on it, and /end_session later
// presents that same cookie. A fresh jar at the logout hop would leave
// the OP with no session to terminate and therefore nothing to fan out.
func newBCLBrowser(t *testing.T, tk *testkit.Provider) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar.New: %v", err)
	}
	return tk.HTTPClient(jar)
}

// registerBCLClient seeds a client and stamps logoutURI onto its
// backchannel_logout_uri. An empty logoutURI registers a client that has
// not opted into back-channel logout at all.
func registerBCLClient(t *testing.T, tk *testkit.Provider, id, redirectURI, logoutURI string) {
	t.Helper()
	rp := tk.RegisterClient(t, testkit.ClientFixture{
		ID:                      id,
		RedirectURIs:            []string{redirectURI},
		Scopes:                  []string{"openid", "profile", "email"},
		TokenEndpointAuthMethod: "none",
		PublicClient:            true,
	})
	if logoutURI == "" {
		return
	}
	rp.BackchannelLogoutURI = logoutURI
	if err := tk.Store.UpdateClient(context.Background(), rp); err != nil {
		t.Fatalf("UpdateClient(%q): %v", id, err)
	}
}

// establishBCLGrant runs a full code flow so the subject has a grant
// naming clientID. The coordinator walks grants to decide who to
// notify, so without this step a logout has no audience to fan out to.
// The flow runs on browser, whose jar keeps the session cookie
// /end_session needs; the returned id_token doubles as its
// id_token_hint.
func establishBCLGrant(
	t *testing.T,
	tk *testkit.Provider,
	browser *http.Client,
	clientID, redirectURI string,
) string {
	t.Helper()
	params := scenariokit.AuthorizeParams{
		ClientID:    clientID,
		RedirectURI: redirectURI,
		Scope:       "openid profile",
		// Materialised here rather than left zero: AuthorizeParams
		// generates a pair internally when the field is empty, and the
		// verifier /token needs would be lost with it.
		PKCE: scenariokit.NewPKCEPair(""),
	}
	flow := scenariokit.RunCodeFlowWithClient(t, tk, browser, bclSubject, params)
	tok := scenariokit.ExchangeCode(t, tk, scenariokit.ExchangeCodeRequest{
		Code:        flow.Code,
		RedirectURI: redirectURI,
		Verifier:    params.PKCE.Verifier,
		ClientID:    clientID,
		// token_endpoint_auth_method=none carries the client_id in the
		// body; the helper only sets Basic auth when a secret is present.
		Extra: url.Values{"client_id": {clientID}},
	})
	if tok.StatusCode != http.StatusOK {
		t.Fatalf("/token status=%d raw=%v", tok.StatusCode, tok.Raw)
	}
	if tok.IDToken == "" {
		t.Fatalf("/token returned no id_token: %v", tok.Raw)
	}
	return tok.IDToken
}

// endSessionAndDrain terminates the session named by hint and then
// drains the fan-out. /end_session dispatches the deliveries on a
// detached goroutine, so Shutdown is what makes "the POSTs have been
// attempted" a fact rather than a race.
func endSessionAndDrain(t *testing.T, tk *testkit.Provider, browser *http.Client, hint string) {
	t.Helper()
	target := tk.Server.URL + "/oidc/end_session?" + url.Values{"id_token_hint": {hint}}.Encode()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, http.NoBody)
	if err != nil {
		t.Fatalf("build GET %s: %v", target, err)
	}
	resp, err := browser.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusFound {
		t.Fatalf("/end_session status=%d want 200 or 302", resp.StatusCode)
	}
	if err := tk.OP.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown (drain fan-out): %v", err)
	}
}

// TestScenario_BCL_001_LogoutTokenShapeWithSid is OOS — see catalog
// out_of_scope_reason.
func TestScenario_BCL_001_LogoutTokenShapeWithSid(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: BCL-001 (see catalog out_of_scope_reason)")
}

// TestScenario_BCL_002_LogoutTokenOmitsSidWhenNotRequired pins the
// payload of a Logout Token addressed to a client that did not request
// sid: the claim set is exactly {sub, events, iat, exp, aud, iss, jti},
// it still carries the back-channel logout event identifier, and sid is
// absent.
//
// The absence is the load-bearing half. This OP has no RP-specific
// session lineage, so a sid it did emit could only be a value the RP
// cannot correlate — or worse, one belonging to an unrelated browser
// session.
//
// Spec: OIDC Back-Channel Logout 1.0 §2.4.
func TestScenario_BCL_002_LogoutTokenOmitsSidWhenNotRequired(t *testing.T) {
	t.Parallel()

	capture := scenariokit.NewAuditCapture()
	tk := newBCLProvider(t, capture)
	rp := newBCLStubRP(t, http.StatusOK)
	const clientID = "rp-bcl-002"
	redirectURI := "https://rp-bcl-002.testkit.invalid/callback"
	registerBCLClient(t, tk, clientID, redirectURI, rp.uri())

	browser := newBCLBrowser(t, tk)
	hint := establishBCLGrant(t, tk, browser, clientID, redirectURI)
	endSessionAndDrain(t, tk, browser, hint)

	tokens := rp.received()
	if len(tokens) != 1 {
		t.Fatalf("logout tokens received = %d, want 1", len(tokens))
	}
	claims := scenariokit.DecodeJWSClaims(t, tokens[0])

	got := make([]string, 0, len(claims))
	for k := range claims {
		got = append(got, k)
	}
	sort.Strings(got)
	want := []string{"aud", "events", "exp", "iat", "iss", "jti", "sub"}
	if !slices.Equal(got, want) {
		t.Fatalf("logout token claims = %v, want exactly %v", got, want)
	}
	if _, present := claims["sid"]; present {
		t.Error("logout token carries sid; the OP has no RP-specific session lineage to put there")
	}
	events, _ := claims["events"].(map[string]any)
	if _, ok := events["http://schemas.openid.net/event/backchannel-logout"]; !ok {
		t.Errorf("events=%v missing the back-channel logout event identifier", claims["events"])
	}
	if got, _ := claims["sub"].(string); got != bclSubject {
		t.Errorf("sub=%q want %q", got, bclSubject)
	}
	if got, _ := claims["iss"].(string); got != tk.Issuer {
		t.Errorf("iss=%q want %q", got, tk.Issuer)
	}
}

// TestScenario_BCL_003_DeliveryFailureSurfacedToOperators confirms that
// an RP answering the logout POST with 500 leaves an operator-visible
// record. Fan-out is best-effort by design — the coordinator never
// propagates a per-RP error to the caller, and /end_session answers the
// browser identically either way — so the audit stream is the only
// place a broken RP can be detected, retried or alarmed on.
//
// Spec: OIDC Back-Channel Logout 1.0 §2.7.
func TestScenario_BCL_003_DeliveryFailureSurfacedToOperators(t *testing.T) {
	t.Parallel()

	capture := scenariokit.NewAuditCapture()
	tk := newBCLProvider(t, capture)
	rp := newBCLStubRP(t, http.StatusInternalServerError)
	const clientID = "rp-bcl-003"
	redirectURI := "https://rp-bcl-003.testkit.invalid/callback"
	registerBCLClient(t, tk, clientID, redirectURI, rp.uri())

	browser := newBCLBrowser(t, tk)
	hint := establishBCLGrant(t, tk, browser, clientID, redirectURI)
	endSessionAndDrain(t, tk, browser, hint)

	if got := len(rp.received()); got != 1 {
		t.Fatalf("logout POSTs received = %d, want 1", got)
	}
	failures := capture.EventsByName("logout.back_channel.failed")
	if len(failures) != 1 {
		t.Fatalf("logout.back_channel.failed events = %d, want 1 (all events: %v)",
			len(failures), auditEventNames(capture))
	}
	if delivered := capture.EventsByName("logout.back_channel.delivered"); len(delivered) != 0 {
		t.Errorf("a 500 from the RP was recorded as delivered (%d events)", len(delivered))
	}
	if !auditEventNamesClientID(failures[0], clientID) {
		t.Errorf("failure event does not name client_id=%q; attrs=%v", clientID, failures[0].Attrs)
	}
}

// auditEventNames lists the captured event names, for failure messages
// that would otherwise say only "want 1, got 0".
func auditEventNames(c *scenariokit.AuditCapture) []string {
	events := c.Events()
	out := make([]string, 0, len(events))
	for _, ev := range events {
		out = append(out, ev.Name)
	}
	return out
}

// auditEventNamesClientID reports whether ev carries client_id=want,
// which is what makes a failure record actionable per RP.
func auditEventNamesClientID(ev scenariokit.AuditEvent, want string) bool {
	for _, a := range ev.Attrs {
		if a.Key == "client_id" && a.Value.String() == want {
			return true
		}
	}
	return false
}

// TestScenario_BCL_004_DiscoveryAdvertisesBCLSupport pins OIDC
// Back-Channel Logout 1.0 §3 plus the OIDC Discovery §3 metadata: a
// BCL-capable OP advertises end_session_endpoint together with
// backchannel_logout_supported=true and
// backchannel_logout_session_supported=false. The coordinator is
// unconditionally wired, but does not claim RP-specific SID support.
//
// Spec: OIDC BCL §3 / OIDC Discovery §3.
func TestScenario_BCL_004_DiscoveryAdvertisesBCLSupport(t *testing.T) {
	t.Parallel()

	tk := testkit.NewProvider(t)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet,
		tk.Server.URL+"/.well-known/openid-configuration", http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := tk.HTTPClient(nil).Do(req)
	if err != nil {
		t.Fatalf("GET discovery: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d want 200", resp.StatusCode)
	}
	doc := map[string]any{}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}
	if got, _ := doc["end_session_endpoint"].(string); got == "" {
		t.Errorf("end_session_endpoint missing or empty (doc=%v)", doc)
	}
	if got, _ := doc["backchannel_logout_supported"].(bool); !got {
		t.Errorf("backchannel_logout_supported=%v want true (doc=%v)", doc["backchannel_logout_supported"], doc)
	}
	if got, ok := doc["backchannel_logout_session_supported"].(bool); !ok || got {
		t.Errorf("backchannel_logout_session_supported=%v want false", doc["backchannel_logout_session_supported"])
	}
}

// TestScenario_BCL_005_AuthorizeIDTokenCarriesSid is OOS — see catalog
// out_of_scope_reason.
func TestScenario_BCL_005_AuthorizeIDTokenCarriesSid(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: BCL-005 (see catalog out_of_scope_reason)")
}

// TestScenario_BCL_006_CodeGrantIDTokenCarriesSid is OOS — see catalog
// out_of_scope_reason.
func TestScenario_BCL_006_CodeGrantIDTokenCarriesSid(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: BCL-006 (see catalog out_of_scope_reason)")
}

// TestScenario_BCL_007_RefreshGrantIDTokenCarriesSid is OOS — see
// catalog out_of_scope_reason.
func TestScenario_BCL_007_RefreshGrantIDTokenCarriesSid(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: BCL-007 (see catalog out_of_scope_reason)")
}

// TestScenario_BCL_008_GlobalLogoutFansOutToVisitedClients is OOS —
// see catalog out_of_scope_reason.
func TestScenario_BCL_008_GlobalLogoutFansOutToVisitedClients(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: BCL-008 (see catalog out_of_scope_reason)")
}

// TestScenario_BCL_009_TargetedLogoutOnlyContactsInitiator is OOS —
// see catalog out_of_scope_reason.
func TestScenario_BCL_009_TargetedLogoutOnlyContactsInitiator(t *testing.T) {
	t.Parallel()
	t.Skip("out-of-scope: BCL-009 (see catalog out_of_scope_reason)")
}

// TestScenario_BCL_010_ClientWithoutBCLUriIsSkipped confirms that a
// client which never registered a backchannel_logout_uri is passed over
// silently while a BCL-capable co-resident client on the same session
// still receives its Logout Token.
//
// The two halves have to be asserted together: a fan-out that skipped
// everyone would satisfy "no delivery attempted to the opted-out
// client" on its own, and would be a total outage of the feature.
//
// Spec: OIDC Back-Channel Logout 1.0 §2.4.
func TestScenario_BCL_010_ClientWithoutBCLUriIsSkipped(t *testing.T) {
	t.Parallel()

	capture := scenariokit.NewAuditCapture()
	tk := newBCLProvider(t, capture)
	rp := newBCLStubRP(t, http.StatusOK)

	const capableID = "rp-bcl-010-capable"
	const optedOutID = "rp-bcl-010-plain"
	capableRedirect := "https://rp-bcl-010-capable.testkit.invalid/callback"
	optedOutRedirect := "https://rp-bcl-010-plain.testkit.invalid/callback"
	registerBCLClient(t, tk, capableID, capableRedirect, rp.uri())
	registerBCLClient(t, tk, optedOutID, optedOutRedirect, "")

	// One subject, two grants: the fan-out has to choose between them.
	browser := newBCLBrowser(t, tk)
	hint := establishBCLGrant(t, tk, browser, capableID, capableRedirect)
	establishBCLGrant(t, tk, browser, optedOutID, optedOutRedirect)

	endSessionAndDrain(t, tk, browser, hint)

	tokens := rp.received()
	if len(tokens) != 1 {
		t.Fatalf("BCL-capable client received %d logout tokens, want 1", len(tokens))
	}
	claims := scenariokit.DecodeJWSClaims(t, tokens[0])
	if got, _ := claims["aud"].(string); got != capableID {
		t.Errorf("logout token aud=%v want %q", claims["aud"], capableID)
	}

	// The opted-out client has no endpoint, so "was it skipped" is
	// answered by the audit stream: exactly one delivery outcome was
	// recorded, and it names the capable client.
	outcomes := append(
		capture.EventsByName("logout.back_channel.delivered"),
		capture.EventsByName("logout.back_channel.failed")...,
	)
	if len(outcomes) != 1 {
		t.Fatalf("delivery outcomes = %d, want exactly 1 (all events: %v)",
			len(outcomes), auditEventNames(capture))
	}
	if !auditEventNamesClientID(outcomes[0], capableID) {
		t.Errorf("the single delivery outcome does not name %q; attrs=%v", capableID, outcomes[0].Attrs)
	}
}
