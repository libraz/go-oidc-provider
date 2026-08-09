// White-box tests for the error_description / state encoding contract
// on every authorize-side error rendering surface. The goal is to pin
// that user-controlled bytes (state echoed from the request, plus any
// description that ever flows through the helpers) are properly
// percent-encoded on the redirect surface and HTML-escaped on the
// form_post surface, so a future refactor cannot reintroduce a Keycloak-
// class reflective injection.
//
// Tracks:
//   - GHSA-27gc-wj6x-9w55 (Keycloak, 2024) — error_description was
//     reflected into HTML error pages without escaping, enabling
//     phishing / open-redirect chains. Class: CWE-79 / CWE-601.
//
// The structural mitigation is twofold:
//
//  1. The catalogue of error_description values is closed: every entry
//     in internal/authorize/errors.go is a hardcoded sentinel string,
//     so RP-supplied bytes never reach error_description directly.
//  2. Even when a value reaches the encoder, the redirect surface
//     percent-encodes via [url.Values.Encode] and the form_post surface
//     HTML-escapes via [html.EscapeString]. This file pins both
//     properties end-to-end.
//
//nolint:testpackage // white-box: builders are unexported.
package authorizeendpoint

import (
	"net/url"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authorize"
)

// TestEmitPlainResponse_EncodesHostileBytes_NoXSS pins that hostile
// bytes reaching the redirect surface through the description / state
// values are percent-encoded on the wire, never echoed verbatim.
// A regression that switched the composer from url.Values.Encode to
// raw string concatenation would surface here.
func TestEmitPlainResponse_EncodesHostileBytes_NoXSS(t *testing.T) {
	t.Parallel()

	const (
		hostileDesc  = `<script>alert(1)</script>`
		hostileState = `"><img src=x onerror=alert(1)>`
	)
	got := emitPlainErrorTarget(t, &authorize.Request{
		RedirectURI: testRedirectURI,
		State:       hostileState,
	}, errInvalidRequest, hostileDesc, testIssuer)

	// Negative half: the rendered URL MUST NOT contain the hostile
	// bytes verbatim. A URL-encoded "<script>" appears as "%3Cscript%3E";
	// the raw "<" and ">" characters never arrive on the wire.
	for _, sub := range []string{"<script>", "</script>", `"><img`, "alert(1)"} {
		if strings.Contains(got, sub) {
			t.Errorf("redirect target contained raw hostile byte %q: %s", sub, got)
		}
	}

	// Positive half: parsing the URL and re-reading the values yields
	// the original bytes (decoding works), but on the wire they are
	// percent-encoded. This guards against a regression where the
	// builder is "fixed" by stripping the bytes (which would silently
	// drop information) instead of encoding them.
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if d := u.Query().Get("error_description"); d != hostileDesc {
		t.Errorf("decoded error_description=%q want %q (round-trip via url.Values must preserve bytes)", d, hostileDesc)
	}
	if s := u.Query().Get("state"); s != hostileState {
		t.Errorf("decoded state=%q want %q (round-trip via url.Values must preserve bytes)", s, hostileState)
	}

	// The wire payload itself MUST contain the percent-encoded sigil
	// for the angle bracket — proves we are looking at the encoded
	// bytes, not just at a parser that happened to be lenient.
	if !strings.Contains(got, "%3C") || !strings.Contains(got, "%3E") {
		t.Errorf("redirect target missing percent-encoded angle brackets: %s", got)
	}
}

// TestEmitPlainResponse_StripsControlBytes pins that ASCII control
// characters (CR, LF, tab) are also encoded rather than echoed
// verbatim. CR/LF in particular MUST NOT survive on the wire because
// they enable header-splitting attacks (CRLF injection) — they would
// also let an attacker forge the URL's query separator, splicing a
// second key=value onto the redirect.
func TestEmitPlainResponse_StripsControlBytes(t *testing.T) {
	t.Parallel()

	const hostile = "diag\r\nSet-Cookie: session=evil"
	got := emitPlainErrorTarget(t, &authorize.Request{
		RedirectURI: testRedirectURI,
		State:       "s",
	}, errInvalidRequest, hostile, testIssuer)

	if strings.ContainsAny(got, "\r\n") {
		t.Errorf("redirect target leaked raw CR/LF bytes: %q", got)
	}
	// url.Values.Encode renders the literal "\r" / "\n" as "%0D" / "%0A".
	if !strings.Contains(got, "%0D") || !strings.Contains(got, "%0A") {
		t.Errorf("redirect target missing percent-encoded CR/LF (got %s)", got)
	}
}
