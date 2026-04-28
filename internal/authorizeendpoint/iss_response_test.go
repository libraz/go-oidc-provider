// White-box tests for the RFC 9207 "iss" parameter on authorization
// responses. RFC 9207 (OAuth 2.0 Authorization Server Issuer
// Identification) requires every authorization response — success and
// error — to carry an "iss" parameter equal to the OP's discovery
// issuer. This is defense-in-depth against the "mix-up attack" class
// described in RFC 9700 §4.4: without "iss" on the wire, a client that
// has registered with multiple ASs cannot tell which one issued the
// code it just received, so an attacker that controls a malicious AS
// can swap the response onto an honest AS's wire without detection.
//
// FAPI 2.0 §5.3.2.2 promotes the SHOULD to a MUST. Pinning the rule on
// every emit shape (legacy success / legacy error / JARM success /
// JARM error) here means a future refactor cannot silently drop the
// claim from a single branch.
//
// Tracks: RFC 9207 §2.3-2.4, RFC 9700 §4.4 (Security BCP), and the
// 2025 mix-up attack surface re-confirmed by the formal analysis of
// FAPI 2.0 (eprint.iacr.org/2024/1540) — no single CVE because mix-up
// is a class-level RFC concern rather than a discrete advisory, but
// the absence of "iss" is an exploitable precondition for it.
//
//nolint:testpackage // white-box: builders are unexported.
package authorizeendpoint

import (
	"net/url"
	"testing"
)

const (
	testIssuer      = "https://op.test/oidc"
	testRedirectURI = "https://rp.example.com/callback"
)

// TestBuildSuccessRedirect_AlwaysCarriesIssuer pins that
// buildSuccessRedirect emits "iss" on every successful legacy
// (non-JARM) authorization response.
func TestBuildSuccessRedirect_AlwaysCarriesIssuer(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		redirectURI string
		state       string
	}{
		{"plain", testRedirectURI, ""},
		{"with_state", testRedirectURI, "abc123"},
		{"with_existing_query", testRedirectURI + "?ref=alice", "xyz"},
		{"path_only", "https://rp.example.com/cb", "s"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := buildSuccessRedirect(tc.redirectURI, "the-code", tc.state, testIssuer)
			u, err := url.Parse(got)
			if err != nil {
				t.Fatalf("Parse(%q): %v", got, err)
			}
			if iss := u.Query().Get("iss"); iss != testIssuer {
				t.Fatalf("iss=%q want %q (full=%s)", iss, testIssuer, got)
			}
			if code := u.Query().Get("code"); code != "the-code" {
				t.Errorf("code=%q want %q", code, "the-code")
			}
		})
	}
}

// TestBuildRedirectError_AlwaysCarriesIssuer pins that buildRedirectError
// emits "iss" on every legacy error response. The error path is the
// most attractive target for the mix-up attack: an attacker can force
// the OP into the error branch (e.g. by tampering with consent) and
// rely on the absence of "iss" to misroute the response.
func TestBuildRedirectError_AlwaysCarriesIssuer(t *testing.T) {
	t.Parallel()

	codes := []string{
		errInvalidRequest,
		errLoginRequired,
		errConsentRequired,
		errInteractionRequired,
		errAccessDenied,
		errAccountSelectionRequired,
		errServerError,
		errUnsupportedResponseType,
		errUnsupportedResponseMode,
		errInvalidScope,
		errInvalidRequestObject,
		errInvalidRequestURI,
	}
	for _, code := range codes {
		t.Run(code, func(t *testing.T) {
			t.Parallel()
			got, err := buildRedirectError(testRedirectURI, code, "diag", "state-1", testIssuer)
			if err != nil {
				t.Fatalf("buildRedirectError: %v", err)
			}
			u, err := url.Parse(got)
			if err != nil {
				t.Fatalf("Parse(%q): %v", got, err)
			}
			if iss := u.Query().Get("iss"); iss != testIssuer {
				t.Fatalf("iss=%q want %q (full=%s)", iss, testIssuer, got)
			}
			if c := u.Query().Get("error"); c != code {
				t.Errorf("error=%q want %q", c, code)
			}
			if s := u.Query().Get("state"); s != "state-1" {
				t.Errorf("state=%q want %q", s, "state-1")
			}
		})
	}
}

// TestBuildRedirectError_EmptyIssuerOmitted exists as a negative pin:
// when the OP has no configured issuer (only possible in unit-test
// composition; production op.New rejects an empty issuer at build
// time), the builder must NOT stamp an empty "iss" — that would create
// a false sense of presence on the wire.
func TestBuildRedirectError_EmptyIssuerOmitted(t *testing.T) {
	t.Parallel()

	got, err := buildRedirectError(testRedirectURI, errAccessDenied, "", "s", "")
	if err != nil {
		t.Fatalf("buildRedirectError: %v", err)
	}
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, ok := u.Query()["iss"]; ok {
		t.Fatalf("iss must be absent when issuer empty; full=%s", got)
	}
}

// TestBuildSuccessRedirect_EmptyIssuerOmitted is the success-path twin
// of [TestBuildRedirectError_EmptyIssuerOmitted].
func TestBuildSuccessRedirect_EmptyIssuerOmitted(t *testing.T) {
	t.Parallel()

	got := buildSuccessRedirect(testRedirectURI, "c", "s", "")
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, ok := u.Query()["iss"]; ok {
		t.Fatalf("iss must be absent when issuer empty; full=%s", got)
	}
}
