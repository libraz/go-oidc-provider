package jose_test

import (
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/jose"
)

// TestDecryptChain_DepthBoundary pins the depth-cap behaviour described
// on [jose.MaxJOSENestingDepth]. The matrix walks every shape that
// matters for the JAR / PAR request-object path: a bare leaf (one
// non-JWE layer the caller will Parse), a small chain that comfortably
// fits the budget, the boundary case at MaxJOSENestingDepth-1 JWE
// peels (which the JAR caller passes as the budget), and over-budget
// chains that MUST surface [jose.ErrJWENestingTooDeep].
//
// The "nestedJWE" helper wraps the inner string by re-emitting it as a
// fresh JWE; both the alg/enc and the recipient key are the same
// across every layer so the test isolates the depth-tracking logic
// from any per-layer decoding variability.
func TestDecryptChain_DepthBoundary(t *testing.T) {
	t.Parallel()

	rsaKey := mustRSAKey(t)
	resolver := singleKeyResolver{kid: "k1", key: rsaKey}

	cases := []struct {
		name      string
		jweLayers int  // number of nested JWE layers
		budget    int  // budget passed to DecryptChain
		wantErr   bool // expect ErrJWENestingTooDeep
	}{
		{name: "depth-1 (no JWE, bare leaf)", jweLayers: 0, budget: jose.MaxJOSENestingDepth - 1, wantErr: false},
		{name: "depth-5 (4 JWE + leaf)", jweLayers: 4, budget: jose.MaxJOSENestingDepth - 1, wantErr: false},
		{name: "depth-10 boundary (9 JWE + leaf)", jweLayers: 9, budget: jose.MaxJOSENestingDepth - 1, wantErr: false},
		{name: "depth-11 over-by-one (10 JWE + leaf)", jweLayers: 10, budget: jose.MaxJOSENestingDepth - 1, wantErr: true},
		// "well over" pins behaviour beyond a single over-by-one
		// crossing — e.g. a regression that resets the counter on
		// every iteration would still pass the depth-11 case but
		// surface here. 13 is sufficient (any value > MaxJOSENestingDepth)
		// and keeps the per-RSA-encryption seed cost bounded.
		{name: "depth-14 well over (13 JWE + leaf)", jweLayers: 13, budget: jose.MaxJOSENestingDepth - 1, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			leaf := "leaf-payload"
			payload := leaf
			for range tc.jweLayers {
				payload = nestedJWE(t, payload, &rsaKey.PublicKey, "k1")
			}

			out, err := jose.DecryptChain(payload, resolver, tc.budget)
			if tc.wantErr {
				if !errors.Is(err, jose.ErrJWENestingTooDeep) {
					t.Fatalf("DecryptChain depth=%d budget=%d: want ErrJWENestingTooDeep, got %v",
						tc.jweLayers+1, tc.budget, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("DecryptChain depth=%d budget=%d: unexpected err %v",
					tc.jweLayers+1, tc.budget, err)
			}
			if string(out.Plaintext) != leaf {
				t.Fatalf("plaintext mismatch: got %q want %q", out.Plaintext, leaf)
			}
			if out.JWELayers != tc.jweLayers {
				t.Fatalf("JWELayers mismatch: got %d want %d", out.JWELayers, tc.jweLayers)
			}
		})
	}
}

// TestDecryptChain_BareJWS confirms that a non-JWE-shaped raw
// (i.e. a JWS or even arbitrary text) round-trips through
// [jose.DecryptChain] without invoking the resolver. The verifier's
// JWS-only path relies on the bare-leaf early-return.
func TestDecryptChain_BareJWS(t *testing.T) {
	t.Parallel()

	resolver := singleKeyResolver{} // Resolve always returns ok=false
	out, err := jose.DecryptChain("not.a.jwe", resolver, jose.MaxJOSENestingDepth-1)
	if err != nil {
		t.Fatalf("DecryptChain bare JWS: %v", err)
	}
	if string(out.Plaintext) != "not.a.jwe" {
		t.Fatalf("plaintext mismatch: got %q", out.Plaintext)
	}
	if out.JWELayers != 0 {
		t.Fatalf("JWELayers=%d want 0", out.JWELayers)
	}
}

// TestDecryptChain_NonPositiveBudget guards the misuse path: a
// caller that passes budget=0 (or negative) MUST get
// [jose.ErrJWENestingTooDeep] uniformly so the bug fails closed at the
// boundary rather than silently admitting unbounded nesting.
func TestDecryptChain_NonPositiveBudget(t *testing.T) {
	t.Parallel()

	rsaKey := mustRSAKey(t)
	resolver := singleKeyResolver{kid: "k1", key: rsaKey}
	jwe := nestedJWE(t, "leaf", &rsaKey.PublicKey, "k1")

	for _, budget := range []int{0, -1, -100} {
		_, err := jose.DecryptChain(jwe, resolver, budget)
		if !errors.Is(err, jose.ErrJWENestingTooDeep) {
			t.Fatalf("DecryptChain budget=%d: want ErrJWENestingTooDeep, got %v", budget, err)
		}
	}
}

// nestedJWE wraps payload as a fresh JWE addressed to pub+kid using
// the production [jose.Encrypt] entry point. Reusing the production
// encrypter (rather than hand-crafting compact strings) ensures the
// test exercises the same parse path the JAR verifier hits at runtime.
func nestedJWE(t *testing.T, payload string, pub *rsa.PublicKey, kid string) string {
	t.Helper()
	out, err := jose.Encrypt([]byte(payload), jose.EncryptionRecipient{
		Alg:   jose.JWEAlgRSAOAEP256,
		Enc:   jose.JWEEncA256GCM,
		KeyID: kid,
		Key:   pub,
	})
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	return out
}
