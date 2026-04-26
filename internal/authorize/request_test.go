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
	if err := req.Validate(goodClient()); err != nil {
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
	if err := req.Validate(goodClient()); err != nil {
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
				gotErr = req.Validate(goodClient())
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
		if err := req.Validate(goodClient()); err != nil {
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
		if err := req.Validate(goodClient()); err != nil {
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
	if err := req.Validate(goodClient()); err != nil {
		t.Errorf("Validate: %v", err)
	}
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
