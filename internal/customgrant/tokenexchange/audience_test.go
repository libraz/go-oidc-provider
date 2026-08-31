//nolint:testpackage // exercises unexported audience helpers
package tokenexchange

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/resourceindicator"
	"github.com/libraz/go-oidc-provider/op/store"
)

// resourceEqualityCase is one (registered, requested) pair together
// with the single verdict every surface that compares a resource
// indicator against a registered audience is allowed to give.
type resourceEqualityCase struct {
	name       string
	registered string
	requested  string
	want       bool
}

// resourceEqualityCases is written the way an operator registers a value
// and the way a client sends it.
//
// The fragment and userinfo rows are the ones a private normalisation
// helper gets wrong: both components are FORBIDDEN on a resource
// indicator, and a helper that falls back to a verbatim comparison
// admits them at its own surface while the canonical implementation
// rejects them at every other.
var resourceEqualityCases = []resourceEqualityCase{
	{name: "default https port stripped", registered: "https://api.example.com:443/v1/", requested: "https://api.example.com/v1", want: true},
	{name: "default http port stripped", registered: "http://api.example.com:80", requested: "http://api.example.com/", want: true},
	{name: "non-default port preserved", registered: "https://api.example.com:8443", requested: "https://api.example.com", want: false},
	{name: "trailing slash ignored", registered: "https://api.example.com/v1/", requested: "https://api.example.com/v1", want: true},
	{name: "scheme and host case folded", registered: "HTTPS://API.EXAMPLE.COM/v1", requested: "https://api.example.com/v1", want: true},
	{name: "path case preserved", registered: "https://api.example.com/V1", requested: "https://api.example.com/v1", want: false},
	{name: "requested fragment rejected", registered: "https://api.example.com/v1", requested: "https://api.example.com/v1#frag", want: false},
	{name: "registered fragment matches nothing", registered: "https://api.example.com/v1#frag", requested: "https://api.example.com/v1#frag", want: false},
	{name: "requested userinfo rejected", registered: "https://api.example.com/v1", requested: "https://trusted@api.example.com/v1", want: false},
	{name: "registered userinfo matches nothing", registered: "https://trusted@api.example.com/v1", requested: "https://trusted@api.example.com/v1", want: false},
	{name: "opaque audience label compares verbatim", registered: "urn:example:api", requested: "urn:example:api", want: true},
}

// TestAudienceEqualityMatchesTheClientCredentialsSurface pins the
// cross-surface invariant: the same (registered, requested) pair MUST
// receive the same verdict at token exchange as at client_credentials,
// whose allowlist predicate is [resourceindicator.Contains]. A client
// that registers "https://api.example.com:443/v1/" and sends the same
// value at both endpoints must not be accepted at one and rejected at
// the other with invalid_target.
func TestAudienceEqualityMatchesTheClientCredentialsSurface(t *testing.T) {
	t.Parallel()

	for _, tc := range resourceEqualityCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			registered := []string{tc.registered}
			// The client_credentials surface. Its allowlist only ever sees
			// values that already passed resource-indicator validation, so
			// an opaque audience label — legal at token exchange, which
			// speaks RFC 8693 audiences — is out of its domain.
			if resourceindicator.Validate(tc.requested) == nil {
				if got := resourceindicator.Contains(registered, tc.requested); got != tc.want {
					t.Errorf("client_credentials allowlist=%v want %v", got, tc.want)
				}
			}
			if got := audienceAllowed([]string{tc.requested}, &store.Client{Resources: registered}); got != tc.want {
				t.Errorf("audienceAllowed=%v want %v", got, tc.want)
			}
			if got := audienceSubset([]string{tc.requested}, registered); got != tc.want {
				t.Errorf("audienceSubset=%v want %v", got, tc.want)
			}
		})
	}
}

func TestAudienceSubsetCanonicalisesBothSides(t *testing.T) {
	t.Parallel()

	if !audienceSubset(
		[]string{"HTTPS://API.EXAMPLE/foo/", "https://other.example/"},
		[]string{"https://api.example/foo", "HTTPS://OTHER.EXAMPLE"},
	) {
		t.Fatal("audienceSubset rejected equivalent canonical resources")
	}
	if audienceSubset(
		[]string{"https://api.example", "https://extra.example"},
		[]string{"https://api.example"},
	) {
		t.Fatal("audienceSubset accepted an audience broader than requested")
	}
	if !audienceSubset(nil, []string{"https://api.example"}) {
		t.Fatal("empty granted audience should be a subset")
	}
}

func TestScopeHelpersPreserveDownscopeSemantics(t *testing.T) {
	t.Parallel()

	if !scopeSubset([]string{"read", "write"}, []string{"profile", "write", "read"}) {
		t.Fatal("scopeSubset rejected scopes present in the source token")
	}
	if scopeSubset([]string{"read", "admin"}, []string{"read", "write"}) {
		t.Fatal("scopeSubset accepted a scope absent from the source token")
	}
	if !scopeSubset(nil, []string{"read"}) {
		t.Fatal("empty requested scope should be a subset")
	}

	got := intersectScope([]string{"write", "read", "admin", "read"}, []string{"read", "write"})
	want := []string{"write", "read", "read"}
	if !slices.Equal(got, want) {
		t.Fatalf("intersectScope = %v, want %v", got, want)
	}
	if got := intersectScope([]string{"admin"}, []string{"read"}); got != nil {
		t.Fatalf("intersectScope with no overlap = %v, want nil", got)
	}
	if got := dedupe([]string{"read", "write", "read", "profile", "write"}); !slices.Equal(got, []string{"read", "write", "profile"}) {
		t.Fatalf("dedupe order = %v, want [read write profile]", got)
	}
	if got := dedupe(nil); got != nil {
		t.Fatalf("dedupe(nil) = %v, want nil", got)
	}
}

func TestWireErrorWritesOAuthJSONEnvelope(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		err         *wireError
		wantStatus  int
		wantBody    map[string]string
		wantString  string
		wantHeaders map[string]string
	}{
		{
			name:       "invalid request",
			err:        &wireError{code: "invalid_request", description: "bad \"subject\"\nnext\tfield"},
			wantStatus: http.StatusBadRequest,
			wantBody: map[string]string{
				"error":             "invalid_request",
				"error_description": "bad \"subject\"\nnext\tfield",
			},
			wantString: "invalid_request: bad \"subject\"\nnext\tfield",
			wantHeaders: map[string]string{
				"Cache-Control": "no-store",
				"Pragma":        "no-cache",
				"Content-Type":  "application/json",
			},
		},
		{
			name:       "invalid client is unauthorized",
			err:        &wireError{code: "invalid_client"},
			wantStatus: http.StatusUnauthorized,
			wantBody:   map[string]string{"error": "invalid_client"},
			wantString: "invalid_client",
		},
		{
			name:       "server error",
			err:        &wireError{code: "server_error", description: "backend unavailable"},
			wantStatus: http.StatusInternalServerError,
			wantBody:   map[string]string{"error": "server_error", "error_description": "backend unavailable"},
			wantString: "server_error: backend unavailable",
		},
		{
			name:       "configuration error",
			err:        &wireError{code: "configuration_error", description: "policy missing"},
			wantStatus: http.StatusInternalServerError,
			wantBody:   map[string]string{"error": "configuration_error", "error_description": "policy missing"},
			wantString: "configuration_error: policy missing",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := tc.err.Error(); got != tc.wantString {
				t.Fatalf("Error() = %q, want %q", got, tc.wantString)
			}
			if got := tc.err.OAuthCode(); got != tc.wantBody["error"] {
				t.Fatalf("OAuthCode() = %q, want %q", got, tc.wantBody["error"])
			}

			rec := httptest.NewRecorder()
			tc.err.WriteOAuthError(rec)
			res := rec.Result()
			defer res.Body.Close()

			if res.StatusCode != tc.wantStatus {
				t.Fatalf("status = %d, want %d", res.StatusCode, tc.wantStatus)
			}
			if tc.wantHeaders != nil {
				for name, want := range tc.wantHeaders {
					if got := res.Header.Get(name); got != want {
						t.Fatalf("%s header = %q, want %q", name, got, want)
					}
				}
			}

			var body map[string]string
			if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			if !equalStringMap(body, tc.wantBody) {
				t.Fatalf("body = %v, want %v", body, tc.wantBody)
			}
		})
	}
}

func equalStringMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, av := range a {
		if b[k] != av {
			return false
		}
	}
	return true
}
