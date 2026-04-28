package authorize_test

import (
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
