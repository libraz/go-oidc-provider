package endpointsupport_test

import (
	"testing"

	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
)

// TestBearerFromHeader pins every recognised / rejected shape so a
// regression that introduces a third scheme or breaks case-insensitive
// matching is caught here rather than in an endpoint integration test.
func TestBearerFromHeader(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		header    string
		wantToken string
		wantOK    bool
	}{
		{"empty", "", "", false},
		{"bearer simple", "Bearer abc", "abc", true},
		{"bearer trim", "Bearer   abc  ", "abc", true},
		{"bearer lowercase", "bearer abc", "abc", true},
		{"dpop simple", "DPoP abc", "abc", true},
		{"dpop mixed case", "dPoP abc", "abc", true},
		{"unknown scheme", "Basic abc", "", false},
		{"bearer no token", "Bearer ", "", false},
		{"only scheme", "Bearer", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tok, ok := endpointsupport.BearerFromHeader(tc.header)
			if tok != tc.wantToken || ok != tc.wantOK {
				t.Fatalf("BearerFromHeader(%q): (%q,%v), want (%q,%v)", tc.header, tok, ok, tc.wantToken, tc.wantOK)
			}
		})
	}
}

// TestIsFormContent / TestIsJSONContent pin the content-type matchers.
func TestIsFormContent(t *testing.T) {
	t.Parallel()
	if !endpointsupport.IsFormContent("application/x-www-form-urlencoded") {
		t.Fatalf("plain form rejected")
	}
	if !endpointsupport.IsFormContent("application/x-www-form-urlencoded; charset=UTF-8") {
		t.Fatalf("parameterised form rejected")
	}
	if endpointsupport.IsFormContent("application/json") {
		t.Fatalf("json accepted as form")
	}
	if endpointsupport.IsFormContent("") {
		t.Fatalf("empty accepted as form")
	}
}

func TestIsJSONContent(t *testing.T) {
	t.Parallel()
	if !endpointsupport.IsJSONContent("application/json") {
		t.Fatalf("plain json rejected")
	}
	if !endpointsupport.IsJSONContent("Application/JSON; charset=UTF-8") {
		t.Fatalf("case+param json rejected")
	}
	if endpointsupport.IsJSONContent("application/x-www-form-urlencoded") {
		t.Fatalf("form accepted as json")
	}
}
