package authorize_test

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/authorize"
	"github.com/libraz/go-oidc-provider/op/store"
)

// jarmTestClient mirrors the canonical happy-path client the existing
// request validator tests use, but is declared here so this sibling
// file does not depend on private fixtures from request_test.go.
func jarmTestClient() *store.Client {
	return &store.Client{
		ID:           "client-1",
		RedirectURIs: []string{"https://rp.example.com/cb"},
		Scopes:       []string{"openid", "profile"},
	}
}

// jarmCanonicalChallenge is a 43-char base64url-no-pad string that
// satisfies [pkce.ValidateChallenge]; reused to keep request bodies
// short.
const jarmCanonicalChallenge = "0123456789012345678901234567890123456789abc"

// jarmBaseValues returns the canonical happy-path query parameters with
// every required member set; rows mutate just the response_mode.
func jarmBaseValues() url.Values {
	return url.Values{
		"client_id":             {"client-1"},
		"response_type":         {"code"},
		"redirect_uri":          {"https://rp.example.com/cb"},
		"scope":                 {"openid profile"},
		"state":                 {"state-abc"},
		"nonce":                 {"nonce-xyz"},
		"code_challenge":        {jarmCanonicalChallenge},
		"code_challenge_method": {"S256"},
	}
}

func TestParseValues_ResponseMode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		mode string
	}{
		{name: "empty (default)", mode: ""},
		{name: "query", mode: "query"},
		{name: "form_post", mode: "form_post"},
		{name: "query.jwt", mode: "query.jwt"},
		{name: "fragment.jwt", mode: "fragment.jwt"},
		{name: "form_post.jwt", mode: "form_post.jwt"},
		{name: "bare jwt", mode: "jwt"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			values := jarmBaseValues()
			if tt.mode != "" {
				values.Set("response_mode", tt.mode)
			}
			req, err := authorize.ParseValues(values)
			if err != nil {
				t.Fatalf("ParseValues: %v", err)
			}
			if req.ResponseMode != tt.mode {
				t.Errorf("ResponseMode=%q want %q", req.ResponseMode, tt.mode)
			}
		})
	}
}

func TestValidate_AcceptsKnownResponseModes(t *testing.T) {
	t.Parallel()

	known := []string{"", "query", "form_post", "query.jwt", "fragment.jwt", "form_post.jwt", "jwt"}
	client := jarmTestClient()
	for _, mode := range known {
		t.Run("mode="+mode, func(t *testing.T) {
			t.Parallel()

			values := jarmBaseValues()
			if mode != "" {
				values.Set("response_mode", mode)
			}
			req, err := authorize.ParseValues(values)
			if err != nil {
				t.Fatalf("ParseValues: %v", err)
			}
			if err := req.Validate(client, nil, authorize.Policy{PKCERequired: true}); err != nil {
				t.Errorf("Validate: %v", err)
			}
		})
	}
}

func TestValidate_RejectsUnknownResponseMode(t *testing.T) {
	t.Parallel()

	values := jarmBaseValues()
	values.Set("response_mode", "weird.jwt")
	req, err := authorize.ParseValues(values)
	if err != nil {
		t.Fatalf("ParseValues: %v", err)
	}
	err = req.Validate(jarmTestClient(), nil, authorize.Policy{PKCERequired: true})
	if !errors.Is(err, authorize.ErrResponseModeUnsupported) {
		t.Fatalf("Validate err=%v want ErrResponseModeUnsupported", err)
	}
	// The validator runs after redirect_uri verification, so the error
	// is redirect-safe.
	if !authorize.IsRedirectSafe(err) {
		t.Errorf("ErrResponseModeUnsupported expected to be redirect-safe")
	}
}

// TestValidateExtensions_JARMResponseMode locks the truth table of the
// gate that reconciles the requested response_mode with what the OP can
// and must deliver. The table is the contract both the authorization
// endpoint and the pushed-authorization-request endpoint answer from, so
// every cell is a verdict the two MUST reach identically; a cell that
// changes here changes both surfaces at once, which is the point of the
// gate living on the shared policy.
func TestValidateExtensions_JARMResponseMode(t *testing.T) {
	t.Parallel()

	const (
		unsupported = "response mode not usable on this OP"
		required    = "profile requires a JARM response mode"
	)

	cases := []struct {
		name     string
		enabled  bool
		require  bool
		mode     string
		wantErr  *authorize.Error
		wantWhat string
	}{
		// No JARM signer wired: every JARM mode is refused, every
		// plain mode passes.
		{name: "off-empty", mode: ""},
		{name: "off-query", mode: "query"},
		{name: "off-form_post", mode: "form_post"},
		{name: "off-jwt", mode: "jwt", wantErr: authorize.ErrJARMUnsupported, wantWhat: unsupported},
		{name: "off-query.jwt", mode: "query.jwt", wantErr: authorize.ErrJARMUnsupported, wantWhat: unsupported},
		{name: "off-fragment.jwt", mode: "fragment.jwt", wantErr: authorize.ErrJARMUnsupported, wantWhat: unsupported},
		{name: "off-form_post.jwt", mode: "form_post.jwt", wantErr: authorize.ErrJARMUnsupported, wantWhat: unsupported},

		// Signer wired, profile does not mandate JARM: everything the
		// catalogue admits passes.
		{name: "on-empty", enabled: true, mode: ""},
		{name: "on-query", enabled: true, mode: "query"},
		{name: "on-form_post", enabled: true, mode: "form_post"},
		{name: "on-jwt", enabled: true, mode: "jwt"},
		{name: "on-query.jwt", enabled: true, mode: "query.jwt"},
		{name: "on-fragment.jwt", enabled: true, mode: "fragment.jwt"},
		{name: "on-form_post.jwt", enabled: true, mode: "form_post.jwt"},

		// Profile mandates JARM: the plain modes are refused, and all
		// four JARM aliases are accepted so the gate does not reject a
		// conformant client that picked a different transport.
		{
			name: "required-empty", enabled: true, require: true, mode: "",
			wantErr: authorize.ErrJARMResponseModeRequired, wantWhat: required,
		},
		{
			name: "required-query", enabled: true, require: true, mode: "query",
			wantErr: authorize.ErrJARMResponseModeRequired, wantWhat: required,
		},
		{
			name: "required-form_post", enabled: true, require: true, mode: "form_post",
			wantErr: authorize.ErrJARMResponseModeRequired, wantWhat: required,
		},
		{name: "required-jwt", enabled: true, require: true, mode: "jwt"},
		{name: "required-query.jwt", enabled: true, require: true, mode: "query.jwt"},
		{name: "required-fragment.jwt", enabled: true, require: true, mode: "fragment.jwt"},
		{name: "required-form_post.jwt", enabled: true, require: true, mode: "form_post.jwt"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			values := jarmBaseValues()
			if tc.mode != "" {
				values.Set("response_mode", tc.mode)
			}
			req, err := authorize.ParseValues(values)
			if err != nil {
				t.Fatalf("ParseValues: %v", err)
			}
			policy := authorize.ExtensionPolicy{
				JARMEnabled:              tc.enabled,
				JARMResponseModeRequired: tc.require,
			}
			rejection := req.ValidateExtensions(context.Background(), jarmTestClient(), policy)
			switch {
			case tc.wantErr == nil && rejection != nil:
				t.Fatalf("ValidateExtensions rejected %v, want acceptance", rejection)
			case tc.wantErr != nil && rejection == nil:
				t.Fatalf("ValidateExtensions accepted, want rejection (%s)", tc.wantWhat)
			case tc.wantErr != nil && !errors.Is(rejection, tc.wantErr):
				t.Fatalf("ValidateExtensions rejection=%v want %v", rejection, tc.wantErr)
			}
			if rejection == nil {
				return
			}
			if rejection.Code != "unsupported_response_mode" {
				t.Errorf("wire code=%q want unsupported_response_mode", rejection.Code)
			}
			// The gate runs after redirect_uri matched the client's
			// registration, so the RP learns of the mismatch through
			// its own redirect target.
			if !authorize.IsRedirectSafe(rejection) {
				t.Errorf("%v expected to be redirect-safe", rejection)
			}
		})
	}
}

func TestSnapshot_RoundTripsResponseMode(t *testing.T) {
	t.Parallel()

	values := jarmBaseValues()
	values.Set("response_mode", "query.jwt")
	req, err := authorize.ParseValues(values)
	if err != nil {
		t.Fatalf("ParseValues: %v", err)
	}
	snap := authorize.SnapshotFrom(req, fixedNow)
	if snap.ResponseMode != "query.jwt" {
		t.Errorf("snapshot ResponseMode=%q", snap.ResponseMode)
	}
	got := snap.ToRequest()
	if got.ResponseMode != "query.jwt" {
		t.Errorf("recovered ResponseMode=%q", got.ResponseMode)
	}
}
