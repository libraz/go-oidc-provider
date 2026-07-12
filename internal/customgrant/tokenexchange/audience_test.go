//nolint:testpackage // exercises unexported audience helpers
package tokenexchange

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
)

func TestNormaliseResourceAppliesRFC8707CanonicalForm(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "empty", in: "", want: ""},
		{name: "scheme and host lowercased", in: "HTTPS://API.EXAMPLE", want: "https://api.example"},
		{name: "root slash stripped", in: "https://api.example/", want: "https://api.example"},
		{name: "trailing path slashes stripped", in: "HTTPS://API.EXAMPLE/foo///", want: "https://api.example/foo"},
		{name: "query preserved", in: "HTTPS://API.EXAMPLE/foo/?a=1", want: "https://api.example/foo?a=1"},
		{name: "non-url left untouched", in: "api.example/resource", want: "api.example/resource"},
		{name: "parseable but not absolute left untouched", in: "/relative/path/", want: "/relative/path/"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := normaliseResource(tc.in); got != tc.want {
				t.Fatalf("normaliseResource(%q) = %q, want %q", tc.in, got, tc.want)
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
		tc := tc
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
