package op_test

import (
	"testing"

	"github.com/libraz/go-oidc-provider/op"
)

// TestAuthMethod_ValidConstants asserts every shipped constant
// reports membership in the closed set. The table exists so a future
// addition that forgets to extend [op.AuthMethod.Valid] fails here
// rather than at the first call site.
func TestAuthMethod_ValidConstants(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		method op.AuthMethod
		wire   string
	}{
		{"client_secret_basic", op.AuthClientSecretBasic, "client_secret_basic"},
		{"client_secret_post", op.AuthClientSecretPost, "client_secret_post"},
		{"private_key_jwt", op.AuthPrivateKeyJWT, "private_key_jwt"},
		{"tls_client_auth", op.AuthTLSClientAuth, "tls_client_auth"},
		{"self_signed_tls_client_auth", op.AuthSelfSignedTLSClientAuth, "self_signed_tls_client_auth"},
		{"none", op.AuthNone, "none"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if !tc.method.Valid() {
				t.Errorf("AuthMethod %q must be Valid()", tc.method)
			}
			if got := tc.method.String(); got != tc.wire {
				t.Errorf("AuthMethod.String()=%q want %q", got, tc.wire)
			}
			if op.AuthMethod(tc.wire) != tc.method {
				t.Errorf("AuthMethod(%q) does not round-trip to %q", tc.wire, tc.method)
			}
		})
	}
}

// TestAuthMethod_ValidRejectsArbitraryString locks the closed-set
// guarantee: a wire value not in the catalogue MUST report
// Valid()==false even if it looks plausible.
func TestAuthMethod_ValidRejectsArbitraryString(t *testing.T) {
	t.Parallel()

	cases := []op.AuthMethod{
		"",
		"unknown",
		"PRIVATE_KEY_JWT",
		"client_secret_jwt", // RFC 7523 method we explicitly do not ship.
		" client_secret_basic",
	}
	for _, m := range cases {
		t.Run(string(m), func(t *testing.T) {
			t.Parallel()
			if m.Valid() {
				t.Errorf("AuthMethod %q must NOT be Valid()", m)
			}
		})
	}
}

// TestAuthMethod_StringPreservesWire asserts the String() round-trip
// is byte-for-byte stable for the catalogued constants. This is the
// invariant store backends rely on when persisting
// [store.Client.TokenEndpointAuthMethod]: writing
// AuthClientSecretBasic.String() and reading it back as
// [op.AuthMethod] MUST yield the same constant.
func TestAuthMethod_StringPreservesWire(t *testing.T) {
	t.Parallel()

	const wire = "client_secret_basic"
	m := op.AuthMethod(wire)
	if m.String() != wire {
		t.Fatalf("round-trip lost data: %q -> %q", wire, m.String())
	}
	if m != op.AuthClientSecretBasic {
		t.Fatalf("round-trip lost identity: got %q want %q", m, op.AuthClientSecretBasic)
	}
}
