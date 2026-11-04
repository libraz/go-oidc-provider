package clientauth_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// TestPrivateKeyJWTVerifier_SingleStringAudience pins the FAPI 2.0
// Security Profile §5.3.2.1 posture: with SingleStringAudience set, only
// "aud" equal to Audience as a JSON string authenticates, while the
// same verifier without the flag keeps accepting the token endpoint URL,
// the auxiliary issuer and arrays.
func TestPrivateKeyJWTVerifier_SingleStringAudience(t *testing.T) {
	t.Parallel()

	const (
		clientID = "rp-single-aud"
		keyID    = "rp-single-aud-key"
		issuer   = "https://op.test"
		tokenAud = "https://op.test/oidc/token" //nolint:gosec // not a credential.
		parAud   = "https://op.test/oidc/par"
	)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	st := inmem.New(inmem.WithClock(fixedClock{now: now}))
	registerAssertionClient(t, st, clientID, keyID, &key.PublicKey)
	resolver, err := clientauth.NewStoreJWKSResolver(st.Clients())
	if err != nil {
		t.Fatalf("NewStoreJWKSResolver: %v", err)
	}
	strict := &clientauth.PrivateKeyJWTVerifier{
		Resolver:             resolver,
		JTIStore:             st.ConsumedJTIs(),
		Audience:             issuer,
		AuxAudiences:         []string{tokenAud},
		SingleStringAudience: true,
		Clock:                fixedClock{now: now}.Now,
	}
	dual := &clientauth.PrivateKeyJWTVerifier{
		Resolver:     resolver,
		JTIStore:     st.ConsumedJTIs(),
		Audience:     tokenAud,
		AuxAudiences: []string{issuer},
		Clock:        fixedClock{now: now}.Now,
	}
	sign := func(t *testing.T, aud any, jti string) string {
		t.Helper()
		return signAssertion(t, key, keyID, map[string]any{
			"iss": clientID,
			"sub": clientID,
			"aud": aud,
			"jti": jti,
			"iat": now.Unix(),
			"exp": now.Add(time.Minute).Unix(),
		})
	}

	cases := []struct {
		name       string
		aud        any
		strictPass bool
		dualPass   bool
	}{
		{"issuer string", issuer, true, true},
		{"token endpoint string", tokenAud, false, true},
		{"PAR endpoint string", parAud, false, false},
		{"array holding only the issuer", []string{issuer}, false, true},
		{"array holding issuer and token endpoint", []string{issuer, tokenAud}, false, true},
		{"issuer with trailing slash", issuer + "/", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := strict.Verify(context.Background(), clientID, sign(t, tc.aud, "strict-"+tc.name))
			switch {
			case tc.strictPass && err != nil:
				t.Errorf("single-string verifier refused aud=%v: %v", tc.aud, err)
			case !tc.strictPass && !errors.Is(err, clientauth.ErrAssertionMalformed):
				t.Errorf("single-string verifier with aud=%v: err=%v, want ErrAssertionMalformed", tc.aud, err)
			}

			err = dual.Verify(context.Background(), clientID, sign(t, tc.aud, "dual-"+tc.name))
			switch {
			case tc.dualPass && err != nil:
				t.Errorf("dual verifier refused aud=%v: %v", tc.aud, err)
			case !tc.dualPass && !errors.Is(err, clientauth.ErrAssertionMalformed):
				t.Errorf("dual verifier with aud=%v: err=%v, want ErrAssertionMalformed", tc.aud, err)
			}
		})
	}
}
