// White-box test for [shouldEmitJWT], the predicate that decides
// whether /introspect emits the RFC 9701 JWT envelope or the legacy
// JSON body. The decision composes three independent inputs: the
// signing key (presence), [Deps.RequireSignedIntrospection] (FAPI 2.0
// Message Signing §5 force), the per-client preregistered alg, and
// the Accept header. Locking the truth table here prevents a future
// refactor from silently regressing the profile-force gate or the
// negotiation order.
//
//nolint:testpackage // intentional white-box test for unexported predicate.
package introspectendpoint

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
)

func TestShouldEmitJWT(t *testing.T) {
	t.Parallel()

	// A throwaway ES256 key the test uses to flip
	// SigningKey.Signer between "configured" and "absent". The key
	// is never used to sign anything; only its presence matters to
	// the predicate.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	signer := tokens.SigningKey{KeyID: "k1", Signer: priv}

	cases := []struct {
		name      string
		signer    tokens.SigningKey
		require   bool
		clientAlg string
		accept    string
		want      bool
	}{
		// Signer absent: predicate is false regardless of any other
		// input. RFC 9701 cannot be satisfied without a key.
		{"no-signer-disabled-empty", tokens.SigningKey{}, false, "", "", false},
		{"no-signer-require-set", tokens.SigningKey{}, true, "", "", false},
		{"no-signer-client-alg", tokens.SigningKey{}, false, "ES256", "", false},
		{"no-signer-accept-jwt", tokens.SigningKey{}, false, "", jwtMediaType, false},

		// Signer present, profile force OFF, no client alg, no
		// Accept hint: legacy JSON wins. This is the v1.0 default
		// posture for a non-FAPI deployment.
		{"signer-default-empty", signer, false, "", "", false},

		// Signer present, profile force ON: every other knob is
		// ignored — the JWT envelope is mandatory.
		{"signer-require-empty-accept", signer, true, "", "", true},
		{"signer-require-json-accept", signer, true, "", jsonMediaType, true},
		{"signer-require-no-client-alg", signer, true, "", jwtMediaType, true},
		{"signer-require-with-client-alg", signer, true, "ES256", jsonMediaType, true},

		// Signer present, profile force OFF, client preregistered
		// an alg: client metadata wins per RFC 9701 §5 even when
		// Accept asks for JSON.
		{"signer-client-alg-no-accept", signer, false, "ES256", "", true},
		{"signer-client-alg-json-accept", signer, false, "ES256", jsonMediaType, true},

		// Signer present, profile force OFF, no client alg: fall
		// through to Accept negotiation. The full Accept-header
		// truth table lives in [TestPreferJWT]; the cases here only
		// confirm that the dispatch reaches it.
		{"signer-accept-jwt", signer, false, "", jwtMediaType, true},
		{"signer-accept-json", signer, false, "", jsonMediaType, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			deps := Deps{
				SigningKey:                 tc.signer,
				RequireSignedIntrospection: tc.require,
			}
			client := &store.Client{IntrospectionSignedResponseAlg: tc.clientAlg}
			if got := shouldEmitJWT(deps, client, tc.accept); got != tc.want {
				t.Errorf(
					"shouldEmitJWT(signer=%v, require=%v, clientAlg=%q, accept=%q) = %v, want %v",
					tc.signer.Signer != nil, tc.require, tc.clientAlg, tc.accept, got, tc.want,
				)
			}
		})
	}
}
