// Test file pins the RFC 8693 §2.1 down-scope invariant on the
// post-policy path: a TokenExchangePolicy decision may only narrow the
// scope and audience the request already justified. A decision that
// broadens either set is a privilege escalation and MUST surface as
// invalid_scope / invalid_target before any token is assembled.
//
//nolint:testpackage // exercises unexported buildResponse
package tokenexchange

import (
	"context"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/customgrant"
	"github.com/libraz/go-oidc-provider/op/store"
)

// oauthCodeOf extracts the wire error code from a wireError so the
// assertions below can compare against the RFC 6749 §5.2 code without
// depending on the "<code>: <description>" string shape.
func oauthCodeOf(t *testing.T, err error) string {
	t.Helper()
	coded, ok := err.(interface{ OAuthCode() string })
	if !ok {
		t.Fatalf("error %v does not expose OAuthCode()", err)
	}
	return coded.OAuthCode()
}

func TestBuildResponse_DownscopeInvariant(t *testing.T) {
	t.Parallel()

	truePtr := true

	tests := []struct {
		name              string
		requestedScope    []string
		requestedAudience []string
		decision          *Decision
		wantErrCode       string // "" means success
		wantScope         []string
		wantAudience      []string
	}{
		{
			name:              "policy grants scope broader than requested",
			requestedScope:    []string{"read"},
			requestedAudience: []string{"https://api.example"},
			// "write" is a scope the client is registered for but that the
			// subject_token never carried, so it is absent from the
			// subject-bounded requestedScope handed to buildResponse.
			decision:    &Decision{GrantedScope: []string{"read", "write"}},
			wantErrCode: "invalid_scope",
		},
		{
			name:              "policy grants audience not in requested set",
			requestedScope:    []string{"read"},
			requestedAudience: []string{"https://api.example"},
			decision:          &Decision{GrantedAudience: []string{"https://evil.example"}},
			wantErrCode:       "invalid_target",
		},
		{
			name:              "policy legitimately narrows scope and audience",
			requestedScope:    []string{"read", "write"},
			requestedAudience: []string{"https://api.example", "https://other.example"},
			decision: &Decision{
				GrantedScope:    []string{"read"},
				GrantedAudience: []string{"https://api.example"},
				IssueIDToken:    &truePtr,
			},
			wantErrCode:  "",
			wantScope:    []string{"read"},
			wantAudience: []string{"https://api.example"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newAssembleHandler(t)
			req := customgrant.Request{Client: &store.Client{ID: "caller"}}
			subjectView := TokenView{Subject: "user-1"}

			resp, err := h.buildResponse(
				context.Background(), req, subjectView, nil,
				tc.requestedScope, tc.requestedAudience, tc.decision,
			)

			if tc.wantErrCode == "" {
				if err != nil {
					t.Fatalf("buildResponse: unexpected error %v", err)
				}
				if !equalStrings(resp.Scope, tc.wantScope) {
					t.Errorf("resp.Scope=%v, want %v", resp.Scope, tc.wantScope)
				}
				if !equalStrings(resp.Audience, tc.wantAudience) {
					t.Errorf("resp.Audience=%v, want %v", resp.Audience, tc.wantAudience)
				}
				return
			}
			if err == nil {
				t.Fatalf("buildResponse: expected %s, got nil error", tc.wantErrCode)
			}
			if code := oauthCodeOf(t, err); code != tc.wantErrCode {
				t.Errorf("error code=%q, want %q", code, tc.wantErrCode)
			}
		})
	}
}

// equalStrings reports whether two string slices carry the same
// elements in the same order.
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
