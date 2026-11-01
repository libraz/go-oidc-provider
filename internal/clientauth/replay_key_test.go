package clientauth_test

import (
	"testing"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
)

func TestReplayKey_PinsBytes(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, prefix, id, jti, want string
	}{
		{"plain", "clientassertion:", "client-a", "j1", "clientassertion:client-a:j1"},
		{"separator escaped", "jwtbearer:", "https://idp.example:8443", "j1", "jwtbearer:https%3A//idp.example%3A8443:j1"},
		{"percent escaped first", "jwtbearer:", "a%3Ab", "j1", "jwtbearer:a%253Ab:j1"},
		{"jti verbatim", "clientassertion:", "c", "x:y%z", "clientassertion:c:x:y%z"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := clientauth.ReplayKey(tc.prefix, tc.id, tc.jti); got != tc.want {
				t.Fatalf("ReplayKey = %q, want %q", got, tc.want)
			}
		})
	}
}
