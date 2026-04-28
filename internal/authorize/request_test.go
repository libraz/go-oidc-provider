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
			name:           "missing_state",
			mutate:         func(v url.Values) { v.Del("state") },
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
				gotErr = req.Validate(goodClient(), nil, authorize.Policy{PKCERequired: true})
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

// TestValidate_ScopeAllowedClients pins the ADR-0004 contract at the
// validator boundary. The scenarios are:
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
