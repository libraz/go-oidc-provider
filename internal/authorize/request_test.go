package authorize_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/internal/pkce"
	"github.com/libraz/go-oidc-provider/internal/scoperegistry"
	"github.com/libraz/go-oidc-provider/op/store"
)

// canonicalChallenge returns the S256 challenge for a fixed verifier so
// every test that needs a "good" PKCE challenge gets the same one.
func canonicalChallenge() string {
	verifier := strings.Repeat("a", 64)
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// goodClient returns a *store.Client with the redirect, scopes, and grant
// shape used across the table tests. Tests that need to deviate clone this
// value rather than mutating the shared one.
func goodClient() *store.Client {
	return &store.Client{
		ID:           "client-1",
		RedirectURIs: []string{"https://rp.example.com/cb"},
		Scopes:       []string{"openid", "profile", "email"},
		ResponseTypes: []string{
			"code",
		},
		GrantTypes: []string{"authorization_code", "refresh_token"},
	}
}

// goodValues returns the canonical "everything present and correct" set of
// authorization request parameters. Table tests mutate the returned copy
// before invoking the parser so each row is independent.
func goodValues() url.Values {
	return url.Values{
		"client_id":             {"client-1"},
		"response_type":         {"code"},
		"redirect_uri":          {"https://rp.example.com/cb"},
		"scope":                 {"openid profile"},
		"state":                 {"state-abc"},
		"nonce":                 {"n-0S6_WzA2Mj"},
		"code_challenge":        {canonicalChallenge()},
		"code_challenge_method": {pkce.Method},
	}
}

func TestParseRequest_HappyGET(t *testing.T) {
	t.Parallel()

	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/authorize?"+goodValues().Encode(), nil)
	req, err := authorize.ParseRequest(r)
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}
	if err := req.Validate(goodClient(), nil, authorize.Policy{PKCERequired: true}); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestParseRequest_HappyPOST(t *testing.T) {
	t.Parallel()

	body := goodValues().Encode()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/authorize", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	req, err := authorize.ParseRequest(r)
	if err != nil {
		t.Fatalf("ParseRequest: %v", err)
	}
	if err := req.Validate(goodClient(), nil, authorize.Policy{PKCERequired: true}); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

// TestValidate_SentinelTable enumerates every sentinel error declared in
// the package and confirms (a) the trigger value produces it, and (b)
// IsRedirectSafe returns the documented answer.
func TestValidate_SentinelTable(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name           string
		mutate         func(url.Values)
		want           error
		wantRedirectOK bool
	}{
		{
			name:   "missing_client_id",
			mutate: func(v url.Values) { v.Del("client_id") },
			want:   authorize.ErrClientIDRequired,
		},
		{
			name:   "missing_redirect_uri",
			mutate: func(v url.Values) { v.Del("redirect_uri") },
			want:   authorize.ErrRedirectURIRequired,
		},
		{
			name:   "redirect_uri_not_registered",
			mutate: func(v url.Values) { v.Set("redirect_uri", "https://evil.example.com/cb") },
			want:   authorize.ErrRedirectURIInvalid,
		},
		{
			name:           "response_type_not_code",
			mutate:         func(v url.Values) { v.Set("response_type", "token") },
			want:           authorize.ErrResponseTypeUnsupported,
			wantRedirectOK: true,
		},
		{
			name:           "missing_state_and_nonce",
			mutate:         func(v url.Values) { v.Del("state"); v.Del("nonce") },
			want:           authorize.ErrStateRequired,
			wantRedirectOK: true,
		},
		{
			name:           "missing_openid_scope",
			mutate:         func(v url.Values) { v.Set("scope", "profile email") },
			want:           authorize.ErrScopeMissingOpenID,
			wantRedirectOK: true,
		},
		{
			name:           "scope_not_permitted",
			mutate:         func(v url.Values) { v.Set("scope", "openid admin") },
			want:           authorize.ErrScopeNotPermitted,
			wantRedirectOK: true,
		},
		{
			name:           "missing_nonce",
			mutate:         func(v url.Values) { v.Del("nonce") },
			want:           authorize.ErrNonceRequired,
			wantRedirectOK: true,
		},
		{
			name:           "missing_code_challenge",
			mutate:         func(v url.Values) { v.Del("code_challenge") },
			want:           authorize.ErrPKCERequired,
			wantRedirectOK: true,
		},
		{
			name:           "method_plain",
			mutate:         func(v url.Values) { v.Set("code_challenge_method", "plain") },
			want:           authorize.ErrPKCEMethodUnsupported,
			wantRedirectOK: true,
		},
		{
			name:           "missing_code_challenge_method",
			mutate:         func(v url.Values) { v.Del("code_challenge_method") },
			want:           authorize.ErrPKCEMethodUnsupported,
			wantRedirectOK: true,
		},
		{
			name:           "challenge_format",
			mutate:         func(v url.Values) { v.Set("code_challenge", "tooshort") },
			want:           authorize.ErrPKCEFormat,
			wantRedirectOK: true,
		},
		{
			name:           "prompt_invalid",
			mutate:         func(v url.Values) { v.Set("prompt", "login banana") },
			want:           authorize.ErrPromptInvalid,
			wantRedirectOK: true,
		},
		{
			name:           "prompt_conflict",
			mutate:         func(v url.Values) { v.Set("prompt", "none login") },
			want:           authorize.ErrPromptConflict,
			wantRedirectOK: true,
		},
		{
			name:           "max_age_negative",
			mutate:         func(v url.Values) { v.Set("max_age", "-1") },
			want:           authorize.ErrMaxAgeInvalid,
			wantRedirectOK: true,
		},
		{
			name:           "max_age_non_integer",
			mutate:         func(v url.Values) { v.Set("max_age", "abc") },
			want:           authorize.ErrMaxAgeInvalid,
			wantRedirectOK: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			values := goodValues()
			tc.mutate(values)

			req, parseErr := authorize.ParseValues(values)
			var gotErr error
			switch {
			case parseErr != nil:
				gotErr = parseErr
			default:
				gotErr = req.Validate(goodClient(), nil, authorize.Policy{
					PKCERequired:         true,
					NonceRequired:        true,
					StateOrNonceRequired: true,
				})
			}
			if !errors.Is(gotErr, tc.want) {
				t.Fatalf("err=%v want %v", gotErr, tc.want)
			}
			if got := authorize.IsRedirectSafe(gotErr); got != tc.wantRedirectOK {
				t.Errorf("IsRedirectSafe(%v) = %v want %v", gotErr, got, tc.wantRedirectOK)
			}
		})
	}
}

// TestRequest_Validate_RejectsImplicitAndHybridResponseTypes pins the
// "code-only" stance documented in [Request.validateResponseType]:
// every implicit / hybrid response_type combination MUST be rejected.
//
// Tracks: CVE-2024-10318 (NGINX OIDC reference module, late 2024) —
// ID-token nonce was not validated, allowing session-fixation /
// ID-token-replay against any RP that accepted an attacker-supplied
// fresh-looking token. The structural defence here is one layer
// further out: an OP that never issues an ID token outside the
// /token endpoint (i.e. only response_type=code) eliminates the
// front-channel nonce-binding surface entirely. This test pins that
// surface to "closed".
//
// Also tracks: OIDC Core 1.0 §15.5.2 / OAuth 2.0 Security BCP
// (RFC 9700) §2.1.2 which DEPRECATE the implicit and hybrid flows
// for new deployments.
func TestRequest_Validate_RejectsImplicitAndHybridResponseTypes(t *testing.T) {
	t.Parallel()

	forbidden := []string{
		"token",               // OAuth implicit (legacy).
		"id_token",            // OIDC implicit.
		"id_token token",      // OIDC implicit + access token.
		"code id_token",       // OIDC hybrid.
		"code token",          // OIDC hybrid (access token via fragment).
		"code id_token token", // OIDC hybrid (everything via fragment).
		"none",                // OIDC §3.1.2.1 "none" — used by some session checks; the OP does not advertise.
		"",                    // Empty: parser SHOULD reject.
		"CODE",                // Case-variant: response_type is case-sensitive per RFC 6749 §3.1.1.
		"Code",                // Case-variant.
		"id_token  token",     // Doubled-space typo.
		"code\nid_token",      // Embedded newline (header-injection class).
	}
	for _, rt := range forbidden {
		t.Run("rt="+rt, func(t *testing.T) {
			t.Parallel()
			values := goodValues()
			values.Set("response_type", rt)
			req, parseErr := authorize.ParseValues(values)
			var gotErr error
			if parseErr != nil {
				gotErr = parseErr
			} else {
				gotErr = req.Validate(goodClient(), nil, authorize.Policy{
					PKCERequired:         true,
					NonceRequired:        true,
					StateOrNonceRequired: true,
				})
			}
			if gotErr == nil {
				t.Fatalf("response_type=%q: Validate accepted", rt)
			}
			if !errors.Is(gotErr, authorize.ErrResponseTypeUnsupported) {
				t.Fatalf("response_type=%q: err=%v want ErrResponseTypeUnsupported", rt, gotErr)
			}
		})
	}
}

// TestRequest_Validate_RedirectURIAttackVariants enumerates the
// attacker-supplied redirect_uri shapes that exact-byte matching MUST
// reject. The library's posture is the strictest one in the OAuth
// ecosystem — equality on the registered string, no scheme/host
// case-folding, no path normalisation, no port-default collapsing.
// Every variant below has a documented bypass in another OP family;
// the test pins the rejection so a future "ergonomic" relaxation
// surfaces immediately.
//
// Tracks:
//   - CVE-2024-8883 (Keycloak; wildcard / suffix bypass of an earlier
//     redirect-URI patch via crafted variants).
//   - CVE-2020-15234 (ory/fosite; case-variant redirect_uri matched a
//     case-different registration).
//   - ory/fosite GHSA-rfq3-w54c-f9q5 (loopback redirect rule allowed
//     host/query override; the fix narrows runtime variation to the
//     port only — exact-string match here is even stricter).
//   - RFC 6749 §3.1.2.3 / RFC 9700 §4.1 which mandate "complete client
//     redirection URI matching" for non-loopback URIs.
//
// The library does NOT special-case the loopback "any port" rule of
// RFC 8252 §7.3 at this layer; embedders that want loopback flexibility
// register every port they accept as a separate URI. That is a deliberate
// posture pin — registering "http://127.0.0.1:0/cb" and getting "any port"
// behaviour at runtime would be a regression.
func TestRequest_Validate_RedirectURIAttackVariants(t *testing.T) {
	t.Parallel()

	// Registered: "https://rp.example.com/cb" (see goodClient).
	cases := []struct {
		name string
		uri  string
	}{
		{"scheme_uppercase", "HTTPS://rp.example.com/cb"},
		{"scheme_mixed", "Https://rp.example.com/cb"},
		{"scheme_downgrade", "http://rp.example.com/cb"},
		{"host_uppercase", "https://RP.EXAMPLE.COM/cb"},
		{"host_mixed", "https://Rp.Example.com/cb"},
		{"host_suffix_attack", "https://rp.example.com.attacker.example/cb"},
		{"host_prefix_attack", "https://attacker.rp.example.com/cb"},
		{"trailing_slash", "https://rp.example.com/cb/"},
		{"fragment_appended", "https://rp.example.com/cb#frag"},
		{"query_appended", "https://rp.example.com/cb?evil=1"},
		{"path_case_variant", "https://rp.example.com/CB"},
		{"path_case_variant_mixed", "https://rp.example.com/Cb"},
		{"path_double_slash", "https://rp.example.com//cb"},
		{"path_dot_segment", "https://rp.example.com/./cb"},
		{"path_parent_dot_segment", "https://rp.example.com/x/../cb"},
		{"path_pct_encoded", "https://rp.example.com/c%62"}, // %62 = 'b'
		{"path_trailing_pct_space", "https://rp.example.com/cb%20"},
		{"explicit_default_port", "https://rp.example.com:443/cb"},
		{"alternate_port", "https://rp.example.com:8443/cb"},
		{"userinfo_smuggling", "https://attacker.example@rp.example.com/cb"},
		{"userinfo_with_pass", "https://u:p@rp.example.com/cb"},
		{"empty_string", ""},
		{"javascript_scheme", "javascript:alert(1)"},
		{"data_scheme", "data:text/html,evil"},
		{"file_scheme", "file:///etc/passwd"},
		{"newline_injection", "https://rp.example.com/cb\nLocation:%20https://attacker.example"},
		{"null_byte", "https://rp.example.com/cb\x00"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			values := goodValues()
			values.Set("redirect_uri", tc.uri)
			req, parseErr := authorize.ParseValues(values)
			var gotErr error
			if parseErr != nil {
				gotErr = parseErr
			} else {
				gotErr = req.Validate(goodClient(), nil, authorize.Policy{
					PKCERequired:         true,
					StateOrNonceRequired: true,
				})
			}
			if gotErr == nil {
				t.Fatalf("redirect_uri=%q: Validate accepted; exact-match contract violated", tc.uri)
			}
			// All variants here either fail at parse (empty / malformed)
			// or at the redirect-target gate. The redirect-target error
			// MUST be ErrRedirectURIInvalid (or ErrRedirectURIRequired
			// for the empty case); a parser-level rejection is also
			// acceptable as long as the request never reaches a state
			// where it could redirect to the attacker URI.
			if !errors.Is(gotErr, authorize.ErrRedirectURIInvalid) &&
				!errors.Is(gotErr, authorize.ErrRedirectURIRequired) &&
				parseErr == nil {
				t.Fatalf("redirect_uri=%q: err=%v want Err{RedirectURIInvalid|Required}", tc.uri, gotErr)
			}
			if authorize.IsRedirectSafe(gotErr) {
				t.Fatalf("redirect_uri=%q: IsRedirectSafe true; attacker URI MUST NOT be honoured", tc.uri)
			}
		})
	}
}

// TestRequest_Validate_PKCEPolicyConditional covers the profile-
// conditional gate: with Policy{PKCERequired:false} a request that
// omits code_challenge MUST be accepted (the OIDC vanilla path that
// the OIDC Basic certification suite drives), while with
// Policy{PKCERequired:true} the same request MUST be rejected with
// ErrPKCERequired (the FAPI 2.0 / OAuth 2.1 posture). The two
// branches share a single fixture so a regression that flips the
// default surfaces here.
func TestRequest_Validate_PKCEPolicyConditional(t *testing.T) {
	t.Parallel()

	build := func(t *testing.T) *authorize.Request {
		t.Helper()
		v := goodValues()
		v.Del("code_challenge")
		v.Del("code_challenge_method")
		req, err := authorize.ParseValues(v)
		if err != nil {
			t.Fatalf("ParseValues: %v", err)
		}
		return req
	}

	t.Run("absent_challenge_accepted_when_not_required", func(t *testing.T) {
		t.Parallel()
		req := build(t)
		if err := req.Validate(goodClient(), nil, authorize.Policy{PKCERequired: false}); err != nil {
			t.Fatalf("Validate: %v want nil", err)
		}
	})

	t.Run("absent_challenge_rejected_when_required", func(t *testing.T) {
		t.Parallel()
		req := build(t)
		err := req.Validate(goodClient(), nil, authorize.Policy{PKCERequired: true})
		if !errors.Is(err, authorize.ErrPKCERequired) {
			t.Fatalf("err=%v want ErrPKCERequired", err)
		}
	})

	t.Run("present_challenge_format_validated_even_when_optional", func(t *testing.T) {
		t.Parallel()
		// Half-supplied pairs (challenge with no method) MUST still
		// fail format validation regardless of the required flag —
		// otherwise a downgrade would be possible.
		v := goodValues()
		v.Del("code_challenge_method")
		req, err := authorize.ParseValues(v)
		if err != nil {
			t.Fatalf("ParseValues: %v", err)
		}
		if err := req.Validate(goodClient(), nil, authorize.Policy{PKCERequired: false}); !errors.Is(err, authorize.ErrPKCEMethodUnsupported) {
			t.Errorf("err=%v want ErrPKCEMethodUnsupported", err)
		}
	})
}

// TestRequest_Validate_OpenIDScopeOptional covers the policy-
// conditional gate for the OIDC Core 1.0 §3.1.2.1 "openid" scope
// requirement. With Policy{OpenIDScopeOptional:false} (the default)
// a request that drops "openid" surfaces ErrScopeMissingOpenID — the
// shape pinned by the missing_openid_scope row in the sentinel
// table. With Policy{OpenIDScopeOptional:true} the same request
// MUST be accepted so the embedder can serve plain OAuth 2.0
// authorization_code on the same /authorize endpoint. The other
// scope checks (client.Scopes intersection, AllowedClients
// allowlist) keep firing under either policy; the only relaxation
// is the "openid presence" gate.
func TestRequest_Validate_OpenIDScopeOptional(t *testing.T) {
	t.Parallel()

	t.Run("missing_openid_accepted_when_optional", func(t *testing.T) {
		t.Parallel()

		v := goodValues()
		v.Set("scope", "profile email")
		req, err := authorize.ParseValues(v)
		if err != nil {
			t.Fatalf("ParseValues: %v", err)
		}
		if err := req.Validate(goodClient(), nil, authorize.Policy{
			PKCERequired:        true,
			OpenIDScopeOptional: true,
		}); err != nil {
			t.Fatalf("Validate: %v want nil (openid optional)", err)
		}
	})

	t.Run("scope_intersection_still_enforced_when_optional", func(t *testing.T) {
		t.Parallel()

		// "admin" is not in goodClient().Scopes — even with the
		// openid gate lifted, the client-registered intersection
		// MUST still surface ErrScopeNotPermitted. This pins that
		// the option lifts ONLY the OIDC openid presence check, not
		// the broader scope authorisation surface.
		v := goodValues()
		v.Set("scope", "profile admin")
		req, err := authorize.ParseValues(v)
		if err != nil {
			t.Fatalf("ParseValues: %v", err)
		}
		gotErr := req.Validate(goodClient(), nil, authorize.Policy{
			PKCERequired:        true,
			OpenIDScopeOptional: true,
		})
		if !errors.Is(gotErr, authorize.ErrScopeNotPermitted) {
			t.Fatalf("err=%v want ErrScopeNotPermitted", gotErr)
		}
	})

	t.Run("allowlist_still_enforced_when_optional", func(t *testing.T) {
		t.Parallel()

		// Scope is registered on the client but the registry
		// allowlist excludes it; ErrScopeClientNotAllowed must
		// still fire when the openid gate is lifted.
		clientWithBilling := goodClient()
		clientWithBilling.Scopes = append(clientWithBilling.Scopes, "billing:write")
		reg := scoperegistry.New([]scoperegistry.Entry{
			{Name: "billing:write", Public: true, AllowedClients: []string{"svc-billing"}},
		})
		v := goodValues()
		v.Set("scope", "billing:write")
		req, err := authorize.ParseValues(v)
		if err != nil {
			t.Fatalf("ParseValues: %v", err)
		}
		gotErr := req.Validate(clientWithBilling, reg, authorize.Policy{
			PKCERequired:        true,
			OpenIDScopeOptional: true,
		})
		if !errors.Is(gotErr, authorize.ErrScopeClientNotAllowed) {
			t.Fatalf("err=%v want ErrScopeClientNotAllowed", gotErr)
		}
	})
}

// TestRequest_Validate_NoncePolicyConditional covers the policy-
// conditional gate for nonce: with Policy{NonceRequired:false} a
// request that omits nonce MUST be accepted (the OIDC Core 1.0 errata
// path the OIDC Basic certification suite drives), while with
// Policy{NonceRequired:true} the same request MUST be rejected with
// ErrNonceRequired (the FAPI 2.0 posture).
func TestRequest_Validate_NoncePolicyConditional(t *testing.T) {
	t.Parallel()

	build := func(t *testing.T) *authorize.Request {
		t.Helper()
		v := goodValues()
		v.Del("nonce")
		req, err := authorize.ParseValues(v)
		if err != nil {
			t.Fatalf("ParseValues: %v", err)
		}
		return req
	}

	t.Run("absent_nonce_accepted_when_not_required", func(t *testing.T) {
		t.Parallel()
		req := build(t)
		if err := req.Validate(goodClient(), nil, authorize.Policy{PKCERequired: true, NonceRequired: false}); err != nil {
			t.Fatalf("Validate: %v want nil", err)
		}
	})

	t.Run("absent_nonce_rejected_when_required", func(t *testing.T) {
		t.Parallel()
		req := build(t)
		err := req.Validate(goodClient(), nil, authorize.Policy{PKCERequired: true, NonceRequired: true})
		if !errors.Is(err, authorize.ErrNonceRequired) {
			t.Fatalf("err=%v want ErrNonceRequired", err)
		}
	})
}

// TestParseValues_DuplicateParameter covers both branches of the duplicate
// rule: identical repeats are accepted, conflicting repeats are rejected.
func TestParseValues_DuplicateParameter(t *testing.T) {
	t.Parallel()

	t.Run("identical_accepted", func(t *testing.T) {
		t.Parallel()

		v := goodValues()
		v["state"] = []string{"state-abc", "state-abc"}
		req, err := authorize.ParseValues(v)
		if err != nil {
			t.Fatalf("ParseValues: %v", err)
		}
		if err := req.Validate(goodClient(), nil, authorize.Policy{PKCERequired: true}); err != nil {
			t.Fatalf("Validate: %v", err)
		}
	})

	t.Run("conflicting_rejected", func(t *testing.T) {
		t.Parallel()

		v := goodValues()
		v["state"] = []string{"state-abc", "state-xyz"}
		_, err := authorize.ParseValues(v)
		if !errors.Is(err, authorize.ErrDuplicateParameter) {
			t.Fatalf("err=%v want ErrDuplicateParameter", err)
		}
	})

	t.Run("scope_repeated_entry_rejected", func(t *testing.T) {
		t.Parallel()

		v := goodValues()
		v["scope"] = []string{"openid", "openid profile"}
		_, err := authorize.ParseValues(v)
		if !errors.Is(err, authorize.ErrDuplicateParameter) {
			t.Fatalf("err=%v want ErrDuplicateParameter", err)
		}
	})
}

// TestParseValues_ScopeDeduplicationOrder confirms that order is preserved
// and duplicates collapse to the first occurrence.
func TestParseValues_ScopeDeduplicationOrder(t *testing.T) {
	t.Parallel()

	v := goodValues()
	v.Set("scope", "openid email openid profile email")
	req, err := authorize.ParseValues(v)
	if err != nil {
		t.Fatalf("ParseValues: %v", err)
	}
	want := []string{"openid", "email", "profile"}
	if len(req.Scope) != len(want) {
		t.Fatalf("scope=%v want %v", req.Scope, want)
	}
	for i, s := range want {
		if req.Scope[i] != s {
			t.Errorf("scope[%d]=%q want %q", i, req.Scope[i], s)
		}
	}
}

// TestParseValues_MaxAgeBoundaries exercises the three cases the parser
// must distinguish: absent, zero (accepted), and any negative / non-integer
// (rejected).
func TestParseValues_MaxAgeBoundaries(t *testing.T) {
	t.Parallel()

	t.Run("absent_yields_nil", func(t *testing.T) {
		t.Parallel()

		v := goodValues()
		req, err := authorize.ParseValues(v)
		if err != nil {
			t.Fatalf("ParseValues: %v", err)
		}
		if req.MaxAge != nil {
			t.Errorf("MaxAge=%v want nil", req.MaxAge)
		}
	})

	t.Run("zero_accepted", func(t *testing.T) {
		t.Parallel()

		v := goodValues()
		v.Set("max_age", "0")
		req, err := authorize.ParseValues(v)
		if err != nil {
			t.Fatalf("ParseValues: %v", err)
		}
		if req.MaxAge == nil || *req.MaxAge != 0 {
			t.Errorf("MaxAge=%v want pointer to 0", req.MaxAge)
		}
		if err := req.Validate(goodClient(), nil, authorize.Policy{PKCERequired: true}); err != nil {
			t.Errorf("Validate: %v", err)
		}
	})
}

// TestValidate_PromptCombinations exercises the prompt grammar's accepted
// shape ("login consent") to complement the negative cases in the sentinel
// table.
func TestValidate_PromptCombinations(t *testing.T) {
	t.Parallel()

	v := goodValues()
	v.Set("prompt", "login consent")
	req, err := authorize.ParseValues(v)
	if err != nil {
		t.Fatalf("ParseValues: %v", err)
	}
	if err := req.Validate(goodClient(), nil, authorize.Policy{PKCERequired: true}); err != nil {
		t.Errorf("Validate: %v", err)
	}
}

// TestValidate_ScopeAllowedClients pins the AllowedClients contract
// at the validator boundary. The scenarios are:
//
//   - allowlist contains the requesting client → no error.
//   - allowlist excludes the requesting client → ErrScopeClientNotAllowed.
//   - the registry itself is nil → allowlist check is skipped, so a
//     scope the embedder modelled as "client-locked" still validates
//     when the OP was built without a registry. The intersection check
//     against client.Scopes still runs and is what guards the request
//     in that mode.
func TestValidate_ScopeAllowedClients(t *testing.T) {
	t.Parallel()

	// Use a client whose registered Scopes include both the standard
	// and the locked-down billing:write entry; that way the table can
	// exercise allowlist behaviour without the unrelated
	// ErrScopeNotPermitted firing first.
	clientWithBilling := func() *store.Client {
		c := goodClient()
		c.Scopes = append(c.Scopes, "billing:write")
		return c
	}

	t.Run("listed_client_admitted", func(t *testing.T) {
		t.Parallel()

		reg := scoperegistry.New([]scoperegistry.Entry{
			{Name: "billing:write", Public: true, AllowedClients: []string{"client-1", "svc-admin"}},
		})
		v := goodValues()
		v.Set("scope", "openid billing:write")
		req, err := authorize.ParseValues(v)
		if err != nil {
			t.Fatalf("ParseValues: %v", err)
		}
		if err := req.Validate(clientWithBilling(), reg, authorize.Policy{PKCERequired: true}); err != nil {
			t.Errorf("listed client must be admitted: %v", err)
		}
	})

	t.Run("unlisted_client_rejected", func(t *testing.T) {
		t.Parallel()

		reg := scoperegistry.New([]scoperegistry.Entry{
			{Name: "billing:write", Public: true, AllowedClients: []string{"svc-billing"}},
		})
		v := goodValues()
		v.Set("scope", "openid billing:write")
		req, err := authorize.ParseValues(v)
		if err != nil {
			t.Fatalf("ParseValues: %v", err)
		}
		gotErr := req.Validate(clientWithBilling(), reg, authorize.Policy{PKCERequired: true})
		if !errors.Is(gotErr, authorize.ErrScopeClientNotAllowed) {
			t.Fatalf("err=%v want ErrScopeClientNotAllowed", gotErr)
		}
		if !authorize.IsRedirectSafe(gotErr) {
			t.Error("ErrScopeClientNotAllowed must be redirect-safe (post-redirect-URI validation)")
		}
	})

	t.Run("nil_registry_skips_allowlist", func(t *testing.T) {
		t.Parallel()

		// With nil registry the allowlist is not enforced; the
		// client's intersection is the only gate. Use a client that
		// already has billing:write so intersection passes; this
		// confirms the validator falls through to no-error.
		v := goodValues()
		v.Set("scope", "openid billing:write")
		req, err := authorize.ParseValues(v)
		if err != nil {
			t.Fatalf("ParseValues: %v", err)
		}
		if err := req.Validate(clientWithBilling(), nil, authorize.Policy{PKCERequired: true}); err != nil {
			t.Errorf("nil registry must skip allowlist enforcement, got %v", err)
		}
	})
}

// TestIsRedirectSafe_NonPackageError confirms that callers passing in an
// unrelated error get false: the helper must not make redirect-safety
// claims about errors it did not produce.
func TestIsRedirectSafe_NonPackageError(t *testing.T) {
	t.Parallel()

	if authorize.IsRedirectSafe(errors.New("boom")) {
		t.Error("IsRedirectSafe(non-package error) = true; want false")
	}
	if authorize.IsRedirectSafe(nil) {
		t.Error("IsRedirectSafe(nil) = true; want false")
	}
}
