package clientauth_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// TestPrivateKeyJWTVerifier_IssuerMustMatchWholly pins that the
// assertion's "iss" claim is compared as a whole string against the
// client it claims to be.
//
// Identifiers that look like URLs invite comparisons that are not
// equality — a prefix test, a suffix test, a "contains". Each one is
// wrong in a way the happy path never reveals, because the legitimate
// value satisfies all of them. What they admit is anything an attacker
// can register that stands in the right relationship to the real
// identifier: a longer name that starts with it, a name under a domain
// they own that ends with it. Since client identifiers can be chosen at
// registration time, the attacker picks the string, which makes a
// non-equality comparison a registration away from an impersonation.
//
// Tracks: CVE-2024-53861 (PyJWT) — issuer validation accepted a partial
// match, so a token whose "iss" merely shared a prefix with the
// expected issuer passed verification.
func TestPrivateKeyJWTVerifier_IssuerMustMatchWholly(t *testing.T) {
	t.Parallel()

	const (
		registered = "https://rp.example/client"
		tokenAud   = "https://op.test/oidc/token" //nolint:gosec // not a credential.
		keyID      = "rp-key-1"
	)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	st := inmem.New(inmem.WithClock(fixedClock{now: now}))
	registerAssertionClient(t, st, registered, keyID, &key.PublicKey)
	resolver, err := clientauth.NewStoreJWKSResolver(st.Clients())
	if err != nil {
		t.Fatalf("NewStoreJWKSResolver: %v", err)
	}
	verifier := &clientauth.PrivateKeyJWTVerifier{
		Resolver: resolver,
		JTIStore: st.ConsumedJTIs(),
		Audience: tokenAud,
		Clock:    fixedClock{now: now}.Now,
	}
	assert := func(t *testing.T, iss, sub, jti string) error {
		t.Helper()
		return verifier.Verify(context.Background(), registered, signAssertion(t, key, keyID, map[string]any{
			"iss": iss,
			"sub": sub,
			"aud": tokenAud,
			"jti": jti,
			"iat": now.Unix(),
			"exp": now.Add(time.Minute).Unix(),
		}))
	}

	// The control, first: the exact identifier authenticates. Every
	// refusal below is therefore about the near miss.
	if err := assert(t, registered, registered, "j-iss-control"); err != nil {
		t.Fatalf("the registered identifier was refused: %v", err)
	}

	nearMisses := []struct {
		name string
		iss  string
	}{
		{"a longer identifier sharing the prefix", registered + ".evil"},
		{"a path extension", registered + "/evil"},
		{"an identifier the registered one is a suffix of", "https://attacker.example/" + registered},
		{"a host the registered one is a prefix of", "https://rp.example.attacker.test/client"},
		{"a trailing slash", registered + "/"},
		{"a trailing space", registered + " "},
		{"a leading space", " " + registered},
		{"case folded", "HTTPS://RP.EXAMPLE/CLIENT"},
		{"truncated", "https://rp.example"},
		{"empty", ""},
	}

	for i, tc := range nearMisses {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			jti := "j-iss-" + strconv.Itoa(i)
			// The claim pair moves together: an implementation that
			// compared only one of iss / sub would still be wrong, so
			// drive both to the near-miss value.
			if err := assert(t, tc.iss, tc.iss, jti); !errors.Is(err, clientauth.ErrAssertionMalformed) {
				t.Fatalf("assertion issued by %q authenticated as %q: err=%v, want ErrAssertionMalformed",
					tc.iss, registered, err)
			}
			// And each on its own, so a verifier that checks one and
			// trusts the other is caught too.
			if err := assert(t, tc.iss, registered, jti+"-iss"); !errors.Is(err, clientauth.ErrAssertionMalformed) {
				t.Errorf("assertion with iss=%q (sub exact) authenticated: err=%v", tc.iss, err)
			}
			if err := assert(t, registered, tc.iss, jti+"-sub"); !errors.Is(err, clientauth.ErrAssertionMalformed) {
				t.Errorf("assertion with sub=%q (iss exact) authenticated: err=%v", tc.iss, err)
			}
		})
	}
}
