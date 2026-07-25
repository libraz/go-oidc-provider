package scenarios_test

import (
	"net/http"
	"net/url"
	"testing"
)

// TestTokenExchange_DelegationParametersAreNeverSilentlyDropped pins
// that a token-exchange request which fails to name the identity it is
// exchanging for is refused, rather than proceeding on the caller's own
// authority.
//
// Everything that makes token exchange safe is downstream of one
// question: whose token is this? The subject token is the answer, and
// every subsequent gate — scope must subset the subject's, audience
// must subset the subject's, the act chain records who delegated to
// whom — is computed relative to it. Lose that input and the gates do
// not fail; they pass, because a request with nothing to downscope from
// is trivially within its own limits. What comes back is a token for
// whoever asked, which is precisely the identity token exchange exists
// to avoid handing out.
//
// The degenerate shapes matter more than the obviously-absent one. A
// parameter that arrives empty, or twice, is where a parser's
// convenience — take the first, take the last, coalesce to "" — turns
// a malformed request into a well-formed one for a different subject.
//
// Tracks: CVE-2026-9704 (Keycloak) — the token-exchange endpoint
// dropped the subject_token parameter under certain conditions instead
// of rejecting the request, letting an attacker obtain tokens with
// elevated privileges without valid credentials for the target
// identity.
func TestTokenExchange_DelegationParametersAreNeverSilentlyDropped(t *testing.T) {
	t.Parallel()

	const accessTokenType = "urn:ietf:params:oauth:token-type:access_token" //nolint:gosec // G101: an RFC 8693 token-type URN, not a credential.

	// The control runs first so every refusal below is known to be
	// about the malformed parameter rather than about the fixture.
	t.Run("a well-formed exchange succeeds", func(t *testing.T) {
		t.Parallel()
		p := newTXProvider(t, txAllowAllPolicy{})
		subjectJWS := p.mintSubjectToken(t, p.defaultSubjectClaims("tx-delegation-control"))
		status, body := p.postTokenExchange(t, url.Values{
			"subject_token":      []string{subjectJWS},
			"subject_token_type": []string{accessTokenType},
		})
		if status != http.StatusOK {
			t.Fatalf("status=%d want 200, body=%v", status, body)
		}
		if _, ok := body["access_token"].(string); !ok {
			t.Fatalf("successful exchange returned no access_token; body=%v", body)
		}
	})

	cases := []struct {
		name string
		// mutate rewrites an otherwise-valid form into the degenerate
		// shape under test. The valid subject token is passed in so a
		// row can duplicate it, blank it, or drop it.
		mutate func(form url.Values, subjectJWS string)
	}{
		{
			name: "subject_token absent",
			mutate: func(form url.Values, _ string) {
				form.Del("subject_token")
			},
		},
		{
			name: "subject_token present but empty",
			mutate: func(form url.Values, _ string) {
				form.Set("subject_token", "")
			},
		},
		{
			name: "subject_token repeated with the same value",
			mutate: func(form url.Values, subjectJWS string) {
				form["subject_token"] = []string{subjectJWS, subjectJWS}
			},
		},
		{
			// The shape that decides whether a parser takes the first
			// or the last occurrence: one valid token and one empty
			// string. Either reading is a guess.
			name: "subject_token repeated with an empty second value",
			mutate: func(form url.Values, subjectJWS string) {
				form["subject_token"] = []string{subjectJWS, ""}
			},
		},
		{
			name: "subject_token_type absent",
			mutate: func(form url.Values, _ string) {
				form.Del("subject_token_type")
			},
		},
		{
			name: "subject_token_type present but empty",
			mutate: func(form url.Values, _ string) {
				form.Set("subject_token_type", "")
			},
		},
		{
			name: "subject_token_type repeated",
			mutate: func(form url.Values, _ string) {
				form["subject_token_type"] = []string{accessTokenType, accessTokenType}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			p := newTXProvider(t, txAllowAllPolicy{})
			subjectJWS := p.mintSubjectToken(t, p.defaultSubjectClaims("tx-delegation-"+url.QueryEscape(tc.name)))
			form := url.Values{
				"subject_token":      []string{subjectJWS},
				"subject_token_type": []string{accessTokenType},
			}
			tc.mutate(form, subjectJWS)

			status, body := p.postTokenExchange(t, form)
			if status == http.StatusOK {
				t.Fatalf("exchange succeeded on a request that does not unambiguously name a subject; body=%v", body)
			}
			if got := body["error"]; got != "invalid_request" {
				t.Errorf("error=%v want invalid_request; body=%v", got, body)
			}
			// A rejected exchange must leave nothing behind. A body
			// that still carried a token would mean the request was
			// only partly refused.
			for _, field := range []string{"access_token", "refresh_token", "id_token", "issued_token_type"} {
				if got, ok := body[field]; ok {
					t.Errorf("rejected exchange carries %s=%v", field, got)
				}
			}
		})
	}
}
