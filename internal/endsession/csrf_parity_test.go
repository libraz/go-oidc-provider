package endsession_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/cookie"
	"github.com/libraz/go-oidc-provider/internal/csrf"
	"github.com/libraz/go-oidc-provider/internal/endsession"
)

// parityAllowlist is the origin set the harness OP answers for. It
// equals the issuer the harness configures, which is the list
// [endsession.Handler] derives when Deps.Origins is nil.
func parityAllowlist(t *testing.T) *csrf.Allowlist {
	t.Helper()
	allow, err := csrf.NewAllowlist([]string{"https://op.example.com"})
	if err != nil {
		t.Fatalf("csrf.NewAllowlist: %v", err)
	}
	return allow
}

// withIssuer returns a harness clone whose handler was built with the
// supplied issuer. Everything else is shared with the receiver; the
// clone exists so a row can observe the origin allowlist the handler
// derives when [endsession.Deps.Origins] is nil.
func (h *harness) withIssuer(t *testing.T, issuer string) *harness {
	t.Helper()
	deps := h.deps
	deps.Issuer = issuer
	mux := http.NewServeMux()
	mux.Handle(h.endSessionPath, endsession.Handler(deps))
	clone := *h
	clone.deps = deps
	clone.handler = mux
	return &clone
}

// confirmedLogoutPOST dispatches a POST /end_session carrying a valid
// double-submit pair plus the supplied provenance headers, and reports
// whether the CSRF gate admitted it. Admission is observed through the
// endpoint's own contract: an admitted request renders the signed-out
// page (200), a rejected one renders the static error page (400).
//
// host lets a row spoof the Host header independently of the origin
// headers, which is how a forged cross-site request looks when the
// attacker also controls the reverse-proxy-facing name.
func confirmedLogoutPOST(t *testing.T, h *harness, host string, headers map[string]string) bool {
	t.Helper()
	sessionCookie, _ := h.issueSession(t)
	getResp := h.doGET(t, url.Values{}, sessionCookie)
	defer getResp.Body.Close()
	token := readConfirmCookie(getResp)
	if token == "" {
		t.Fatal("interstitial GET did not set the confirmation cookie")
	}

	form := url.Values{"logout_csrf": {token}}
	r := httptest.NewRequestWithContext(
		context.Background(),
		http.MethodPost,
		h.endSessionPath,
		strings.NewReader(form.Encode()),
	)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Host = host
	for name, value := range headers {
		r.Header.Set(name, value)
	}
	r.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: sessionCookie})
	r.AddCookie(&http.Cookie{Name: cookie.LogoutCSRFProfile.Name, Value: token})

	w := httptest.NewRecorder()
	h.handler.ServeHTTP(w, r)
	resp := w.Result()
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return true
	case http.StatusBadRequest:
		return false
	default:
		t.Fatalf("status=%d want 200 (admitted) or 400 (rejected)", resp.StatusCode)
		return false
	}
}

// originProbe reconstructs the request shape a row describes so the
// shared [csrf.CheckOrigin] can be asked what the /interaction gate
// would decide for it. Only the headers participate in that decision,
// so the probe carries nothing else.
func originProbe(t *testing.T, host string, headers map[string]string) *http.Request {
	t.Helper()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/probe", http.NoBody)
	r.Host = host
	for name, value := range headers {
		r.Header.Set(name, value)
	}
	return r
}

// TestCSRFGateParity_ProvenanceHeaders pins the two HTML-facing CSRF
// gates to a single decision. /interaction/{uid} calls
// [csrf.CheckOrigin] directly; /end_session reaches the same helper
// through its confirmation-POST gate. The table drives one request
// shape per row through the real /end_session handler and asserts the
// admit / reject outcome equals what CheckOrigin answers for the same
// headers, so a future re-fork of either gate's logic fails here
// rather than silently weakening one endpoint.
func TestCSRFGateParity_ProvenanceHeaders(t *testing.T) {
	t.Parallel()

	const opHost = "op.example.com"
	rows := []struct {
		name    string
		host    string
		headers map[string]string
	}{
		{
			name: "no provenance headers",
			host: opHost,
		},
		{
			name:    "cross-site origin",
			host:    opHost,
			headers: map[string]string{"Origin": "https://attacker.example.com"},
		},
		{
			name:    "same-site origin",
			host:    opHost,
			headers: map[string]string{"Origin": "https://op.example.com"},
		},
		{
			name: "same-site origin with cross-site fetch metadata",
			host: opHost,
			headers: map[string]string{
				"Origin":         "https://op.example.com",
				"Sec-Fetch-Site": "cross-site",
			},
		},
		{
			name:    "opaque origin",
			host:    opHost,
			headers: map[string]string{"Origin": "null"},
		},
		{
			// A Referer alone is not enough: modern browsers always
			// emit Origin on a state-changing POST, so this shape is
			// either a legacy UA or a stripped-header forgery.
			name:    "referer only",
			host:    opHost,
			headers: map[string]string{"Referer": "https://op.example.com/oidc/end_session"},
		},
		{
			name: "referer vouched by same-origin fetch metadata",
			host: opHost,
			headers: map[string]string{
				"Referer":        "https://op.example.com/oidc/end_session",
				"Sec-Fetch-Site": "same-origin",
			},
		},
		{
			name: "referer with cross-site fetch metadata",
			host: opHost,
			headers: map[string]string{
				"Referer":        "https://op.example.com/oidc/end_session",
				"Sec-Fetch-Site": "cross-site",
			},
		},
		{
			// Host is attacker-controllable, so a forged request can
			// make Host and Origin agree. Neither gate consults Host.
			name:    "spoofed host agreeing with foreign origin",
			host:    "attacker.example.com",
			headers: map[string]string{"Origin": "https://attacker.example.com"},
		},
		{
			name:    "default port spelled out",
			host:    opHost,
			headers: map[string]string{"Origin": "https://op.example.com:443"},
		},
		{
			name:    "scheme downgraded",
			host:    opHost,
			headers: map[string]string{"Origin": "http://op.example.com"},
		},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			allow := parityAllowlist(t)
			want := csrf.CheckOrigin(originProbe(t, row.host, row.headers), allow) == nil
			got := confirmedLogoutPOST(t, newHarness(t), row.host, row.headers)
			if got != want {
				t.Errorf("end_session admitted=%v, interaction gate admits=%v", got, want)
			}
		})
	}
}

// TestCSRFGateParity_DoubleSubmitHalves pins the token half of the two
// gates: both accept exactly when the cookie and the resubmitted value
// are both present and equal under [csrf.ConstantTimeEqual]. The row
// set covers the shapes that could diverge if either side reverted to
// a plain string comparison or dropped a presence check.
func TestCSRFGateParity_DoubleSubmitHalves(t *testing.T) {
	t.Parallel()

	rows := []struct {
		name string
		// cookieToken / formToken are rendered relative to the token
		// the interstitial minted: "" means omit the half entirely,
		// "issued" means replay it verbatim, anything else is sent
		// literally.
		cookieToken string
		formToken   string
	}{
		{name: "matching halves", cookieToken: "issued", formToken: "issued"},
		{name: "missing cookie", cookieToken: "", formToken: "issued"},
		{name: "missing form field", cookieToken: "issued", formToken: ""},
		{name: "mismatched halves", cookieToken: "issued", formToken: "forged-token-value"},
		{name: "form field a prefix of the cookie", cookieToken: "issued", formToken: "short"},
		{name: "both halves absent", cookieToken: "", formToken: ""},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			sessionCookie, _ := h.issueSession(t)
			getResp := h.doGET(t, url.Values{}, sessionCookie)
			defer getResp.Body.Close()
			issued := readConfirmCookie(getResp)
			if issued == "" {
				t.Fatal("interstitial GET did not set the confirmation cookie")
			}
			cookieValue := resolveParityToken(row.cookieToken, issued)
			formValue := resolveParityToken(row.formToken, issued)

			form := url.Values{}
			if formValue != "" {
				form.Set("logout_csrf", formValue)
			}
			r := httptest.NewRequestWithContext(
				context.Background(),
				http.MethodPost,
				h.endSessionPath,
				strings.NewReader(form.Encode()),
			)
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Host = "op.example.com"
			r.Header.Set("Origin", "https://op.example.com")
			r.AddCookie(&http.Cookie{Name: cookie.SessionProfile.Name, Value: sessionCookie})
			if cookieValue != "" {
				r.AddCookie(&http.Cookie{Name: cookie.LogoutCSRFProfile.Name, Value: cookieValue})
			}
			w := httptest.NewRecorder()
			h.handler.ServeHTTP(w, r)
			resp := w.Result()
			defer resp.Body.Close()

			want := cookieValue != "" && formValue != "" && csrf.ConstantTimeEqual(cookieValue, formValue)
			got := resp.StatusCode == http.StatusOK
			if got != want {
				t.Errorf("status=%d admitted=%v want admitted=%v", resp.StatusCode, got, want)
			}
		})
	}
}

// resolveParityToken expands a row's token spelling into the value the
// request should carry.
func resolveParityToken(spec, issued string) string {
	if spec == "issued" {
		return issued
	}
	return spec
}

// TestCSRFGate_NoUsableOriginAllowlist_FailsClosed confirms the
// fallback list is fail-closed. An OP whose Deps carries neither an
// explicit allowlist nor a canonicalisable issuer has no origin it can
// vouch for, so every confirmation POST is rejected rather than
// falling back to the request's own Host header.
func TestCSRFGate_NoUsableOriginAllowlist_FailsClosed(t *testing.T) {
	t.Parallel()

	h := newHarness(t).withIssuer(t, "not-an-origin")
	if confirmedLogoutPOST(t, h, "op.example.com", map[string]string{
		"Origin": "https://op.example.com",
	}) {
		t.Error("confirmation POST admitted without a usable origin allowlist")
	}
}
