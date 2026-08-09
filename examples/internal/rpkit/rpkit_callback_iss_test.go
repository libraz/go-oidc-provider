//go:build example

package rpkit_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/examples/internal/rpkit"
)

// The tests in this file pin the RFC 9207 §2.4 check on the callback
// path: an authorization response whose "iss" is absent or names a
// different OP must not be exchanged. Without the check an RP is open to
// the mix-up attack RFC 9207 §1 describes, and a FAPI 2.0 RP is missing
// the defence the profile mandates.

const foreignIssuer = "https://attacker.example"

// newCodeFlowOn builds a CodeFlow against a fake OP whose discovery
// document is edited by tweaks, and returns the flow's handler alongside
// the issuer it discovered.
func newCodeFlowOn(t *testing.T, tweaks ...func(doc map[string]any)) (http.Handler, string) {
	t.Helper()
	issuer, cleanup := fakeOP(t, tweaks...)
	t.Cleanup(cleanup)

	cf, err := rpkit.New(context.Background(), rpkit.Options{
		Issuer:      issuer,
		ClientID:    "demo-rp",
		RedirectURL: "http://rp.example/callback",
	})
	if err != nil {
		t.Fatalf("rpkit.New: %v", err)
	}
	return cf.Handler(), issuer
}

// loginState drives the RP's /login route and returns the state the
// redirect carried, so the callback tests exercise a state the RP
// actually issued rather than a fabricated one. A rejection then cannot
// be attributed to an unknown state.
func loginState(t *testing.T, h http.Handler) string {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://rp.example/login", nil)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("/login status = %d, want 302; body = %q", rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse Location: %v", err)
	}
	state := loc.Query().Get("state")
	if state == "" {
		t.Fatal("/login redirect carried no state")
	}
	return state
}

// callback issues a GET against the RP's /callback route with q as the
// query string.
func callback(t *testing.T, h http.Handler, q url.Values) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet,
		"http://rp.example/callback?"+q.Encode(), nil)
	h.ServeHTTP(rec, req)
	return rec
}

func TestCodeFlowCallback_RejectsForeignIssuer(t *testing.T) {
	t.Parallel()

	h, _ := newCodeFlowOn(t)
	rec := callback(t, h, url.Values{
		"state": {loginState(t, h)},
		"code":  {"code-from-the-attacker"},
		"iss":   {foreignIssuer},
	})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %q", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, "iss") {
		t.Errorf("body = %q, want the failure to name the iss parameter", body)
	}
}

func TestCodeFlowCallback_RejectsMissingIssuerWhenOPAdvertisesIt(t *testing.T) {
	t.Parallel()

	h, _ := newCodeFlowOn(t)
	rec := callback(t, h, url.Values{
		"state": {loginState(t, h)},
		"code":  {"code-without-an-issuer"},
	})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %q", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, "iss") {
		t.Errorf("body = %q, want the failure to name the iss parameter", body)
	}
}

// TestCodeFlowCallback_AcceptsMatchingIssuer is the control for the two
// rejections above: with the OP's own issuer the callback proceeds to the
// token exchange, which the fake OP has no endpoint for. The distinct
// failure proves the response was not turned away by the issuer check.
func TestCodeFlowCallback_AcceptsMatchingIssuer(t *testing.T) {
	t.Parallel()

	h, issuer := newCodeFlowOn(t)
	rec := callback(t, h, url.Values{
		"state": {loginState(t, h)},
		"code":  {"code-from-the-op"},
		"iss":   {issuer},
	})

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 from the token exchange; body = %q", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, "token exchange") {
		t.Errorf("body = %q, want the token exchange to be what failed", body)
	}
}

// TestCodeFlowCallback_AllowsAbsentIssuerWhenOPDoesNotAdvertiseIt pins
// the conditional half of RFC 9207 §2.4: an OP that never announced
// support for the parameter is not expected to send it, so its absence
// alone is not a rejection. A wrong value still is, which the case below
// covers.
func TestCodeFlowCallback_AllowsAbsentIssuerWhenOPDoesNotAdvertiseIt(t *testing.T) {
	t.Parallel()

	withoutIssSupport := func(doc map[string]any) {
		delete(doc, "authorization_response_iss_parameter_supported")
	}
	h, _ := newCodeFlowOn(t, withoutIssSupport)
	rec := callback(t, h, url.Values{
		"state": {loginState(t, h)},
		"code":  {"code-from-a-legacy-op"},
	})

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 from the token exchange; body = %q", rec.Code, rec.Body.String())
	}
}

func TestCodeFlowCallback_RejectsForeignIssuerEvenWhenOPDoesNotAdvertiseIt(t *testing.T) {
	t.Parallel()

	withoutIssSupport := func(doc map[string]any) {
		delete(doc, "authorization_response_iss_parameter_supported")
	}
	h, _ := newCodeFlowOn(t, withoutIssSupport)
	rec := callback(t, h, url.Values{
		"state": {loginState(t, h)},
		"code":  {"code-from-the-attacker"},
		"iss":   {foreignIssuer},
	})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %q", rec.Code, rec.Body.String())
	}
}

// newFAPI2Flow builds a FAPI2Flow against the fake OP. The client key is
// ephemeral: the tests stop at the callback's issuer check, so no
// private_key_jwt assertion is ever verified.
func newFAPI2Flow(t *testing.T) (http.Handler, string) {
	t.Helper()
	issuer, cleanup := fakeOP(t)
	t.Cleanup(cleanup)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	f, err := rpkit.NewFAPI2(context.Background(), rpkit.FAPI2Options{
		Issuer:           issuer,
		ClientID:         "demo-fapi",
		RedirectURL:      "http://rp.example/callback",
		ClientPrivateKey: key,
		ClientKeyID:      "fapi-1",
	})
	if err != nil {
		t.Fatalf("rpkit.NewFAPI2: %v", err)
	}
	return f.Handler(), issuer
}

// TestFAPI2Callback_RequiresIssuer pins that the FAPI 2.0 flow treats
// RFC 9207 as mandatory: both a foreign issuer and no issuer at all are
// rejected before the code is used. The matching case is the control —
// it reaches the state lookup, which is the next check in the callback.
func TestFAPI2Callback_RequiresIssuer(t *testing.T) {
	t.Parallel()

	h, issuer := newFAPI2Flow(t)

	cases := map[string]struct {
		iss      string
		omit     bool
		wantBody string
	}{
		"foreign issuer": {iss: foreignIssuer, wantBody: "iss"},
		"absent issuer":  {omit: true, wantBody: "iss"},
		"matching issuer": {
			iss: issuer,
			// The state was never issued by this RP, so the callback
			// falls through to the state check rather than the issuer one.
			wantBody: "unknown state",
		},
	}

	for name, tc := range cases {
		q := url.Values{"state": {"state-not-issued-here"}, "code": {"code-1"}}
		if !tc.omit {
			q.Set("iss", tc.iss)
		}
		rec := callback(t, h, q)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: status = %d, want 400; body = %q", name, rec.Code, rec.Body.String())
		}
		if body := rec.Body.String(); !strings.Contains(body, tc.wantBody) {
			t.Errorf("%s: body = %q, want it to mention %q", name, body, tc.wantBody)
		}
	}
}
