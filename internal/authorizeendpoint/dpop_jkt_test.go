package authorizeendpoint_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authorizeendpoint"
)

// authorizeCommittedJKT is a syntactically valid RFC 7638 thumbprint.
// No test below derives a token from it; only its presence on the wire
// matters.
const authorizeCommittedJKT = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"

// TestAuthorize_RejectsDPoPJKTWhenDPoPDisabled pins the RFC 9449 §10.1
// commitment contract at the endpoint that mints the code. An OP without
// DPoP can neither bind the issued token to the committed key nor demand
// proof of possession at /token, so recording the commitment and handing
// back a code would defer the failure to redemption — where the client
// sees only invalid_grant on a code it has no reason to distrust.
//
// The rejection travels the redirect channel, not a first-party 400:
// the check runs after request validation, so redirect_uri has already
// been matched against the client's registration and is a safe target.
func TestAuthorize_RejectsDPoPJKTWhenDPoPDisabled(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	v := goodAuthorizeValues()
	v.Set("dpop_jkt", authorizeCommittedJKT)

	resp := doAuthorizeGET(t, h, v)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status=%d want 302 (the error belongs on the validated redirect_uri)", resp.StatusCode)
	}
	loc := mustParseLocation(t, resp)
	if got := loc.Host; got != "rp.example.com" {
		t.Fatalf("redirect host=%q want the registered rp.example.com", got)
	}
	if got := loc.Query().Get("error"); got != "invalid_request" {
		t.Errorf("error=%q want invalid_request", got)
	}
	if got := loc.Query().Get("state"); got != "state-abc" {
		t.Errorf("state=%q want the request state echoed back", got)
	}
}

// TestAuthorize_AcceptsDPoPJKTWhenDPoPEnabled is the control for the
// test above: the identical request proceeds to the interaction leg
// once the OP reports that it can honour the commitment, so the
// rejection is attributable to the feature state and to nothing else
// about the request.
func TestAuthorize_AcceptsDPoPJKTWhenDPoPEnabled(t *testing.T) {
	t.Parallel()

	h := newHarness(t, func(d *authorizeendpoint.Deps) {
		d.DPoPEnabled = true
	})
	v := goodAuthorizeValues()
	v.Set("dpop_jkt", authorizeCommittedJKT)

	resp := doAuthorizeGET(t, h, v)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status=%d want 302", resp.StatusCode)
	}
	loc := mustParseLocation(t, resp)
	if got := loc.Query().Get("error"); got != "" {
		t.Fatalf("error=%q want none; dpop_jkt is honoured when DPoP is enabled", got)
	}
	if !strings.HasPrefix(loc.Path, h.interactionPth+"/") {
		t.Errorf("Location=%q want the interaction redirect %s/", loc.String(), h.interactionPth)
	}
}

// TestEndToEnd_JAR_RejectsDPoPJKTInRequestObjectWhenDPoPDisabled covers
// the second way the parameter reaches the endpoint. RFC 9101 §6.1
// merges the request object's claims onto the wire values before
// parsing, so a "dpop_jkt" carried inside a signed request object is
// indistinguishable downstream from one sent in the query — and must be
// refused on the same terms.
func TestEndToEnd_JAR_RejectsDPoPJKTInRequestObjectWhenDPoPDisabled(t *testing.T) {
	t.Parallel()

	h := newJARHarness(t, nil) // JAR only; the provider has no DPoP feature.
	claims := h.happyJARClaims()
	claims["dpop_jkt"] = authorizeCommittedJKT

	resp := h.jarGet(t, h.jarSign(t, claims))
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status=%d want 302 (body=%v)", resp.StatusCode, decodeMap(t, resp))
	}
	loc, err := resp.Location()
	if err != nil {
		t.Fatalf("Location: %v", err)
	}
	if got := loc.Query().Get("error"); got != "invalid_request" {
		t.Errorf("error=%q want invalid_request (%s)", got, loc.String())
	}
}
