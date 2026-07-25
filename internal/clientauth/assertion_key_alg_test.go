package clientauth_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// TestPrivateKeyJWTVerifier_RegisteredKeyCannotWidenTheAlgorithmPolicy
// pins that a key registered by a client does not get to say which
// algorithms the OP will accept.
//
// A JWK carries an optional "alg" member describing what the key is
// for. Reading it as policy rather than as a hint inverts the trust
// relationship: the allow-list stops being the OP's list of algorithms
// it is willing to verify and becomes the client's. Since the client
// writes the JWKS, that is the client deciding how strong its own
// authentication has to be — and the interesting choice is a symmetric
// algorithm, because then "the key" and "the secret" are the same
// published bytes and anybody who fetched the JWKS can sign.
//
// Tracks: CVE-2026-48523 (PyJWT) — when the verification key was
// supplied as a key object carrying its own "alg" metadata, that value
// took precedence over the caller's algorithm allow-list, so a key
// registered for one algorithm verified a token signed with another.
func TestPrivateKeyJWTVerifier_RegisteredKeyCannotWidenTheAlgorithmPolicy(t *testing.T) {
	t.Parallel()

	const (
		clientID = "client-alg-policy"
		keyID    = "rp-symmetric-1"
		tokenAud = "https://op.test/oidc/token" //nolint:gosec // not a credential.
	)

	cases := []struct {
		name string
		// declaredAlg is the "alg" member on the registered JWK, and
		// also the algorithm the forged assertion is signed with, so
		// the two agree with each other and disagree only with the
		// OP's policy.
		declaredAlg josev4.SignatureAlgorithm
		// secretLen is the HMAC key size the algorithm requires, so
		// the forgery fails on policy rather than on key sizing.
		secretLen int
	}{
		{"HS256 declared on the registered key", josev4.HS256, 32},
		{"HS384 declared on the registered key", josev4.HS384, 48},
		{"HS512 declared on the registered key", josev4.HS512, 64},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// The shared secret the client publishes as its own key.
			// Whoever can read the JWKS holds it, which is the whole
			// point: if the declared "alg" were honoured, client
			// authentication would be satisfiable by any reader.
			secret := bytes.Repeat([]byte("s"), tc.secretLen)

			jwks, err := json.Marshal(map[string]any{
				"keys": []map[string]any{{
					"kty": "oct",
					"kid": keyID,
					"use": "sig",
					"alg": string(tc.declaredAlg),
					"k":   base64.RawURLEncoding.EncodeToString(secret),
				}},
			})
			if err != nil {
				t.Fatalf("marshal JWKS: %v", err)
			}

			now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
			st := inmem.New(inmem.WithClock(fixedClock{now: now}))
			if err := st.RegisterClient(context.Background(), &store.Client{
				ID:                      clientID,
				TokenEndpointAuthMethod: string(clientauth.MethodPrivateKeyJWT),
				JWKs:                    jwks,
			}); err != nil {
				t.Fatalf("RegisterClient: %v", err)
			}
			resolver, err := clientauth.NewStoreJWKSResolver(st.Clients())
			if err != nil {
				t.Fatalf("NewStoreJWKSResolver: %v", err)
			}

			signer, err := josev4.NewSigner(
				josev4.SigningKey{Algorithm: tc.declaredAlg, Key: secret},
				(&josev4.SignerOptions{}).WithType("JWT").WithHeader("kid", keyID),
			)
			if err != nil {
				t.Fatalf("NewSigner: %v", err)
			}
			assertion, err := jwt.Signed(signer).Claims(map[string]any{
				"iss": clientID,
				"sub": clientID,
				"aud": tokenAud,
				"jti": "j-alg-policy-" + string(tc.declaredAlg),
				"iat": now.Unix(),
				"exp": now.Add(time.Minute).Unix(),
			}).Serialize()
			if err != nil {
				t.Fatalf("Serialize: %v", err)
			}

			v := &clientauth.PrivateKeyJWTVerifier{
				Resolver: resolver,
				JTIStore: st.ConsumedJTIs(),
				Audience: tokenAud,
				Clock:    fixedClock{now: now}.Now,
			}
			if err := v.Verify(context.Background(), clientID, assertion); err == nil {
				t.Fatalf("an assertion signed with %s authenticated because the registered key declared that algorithm; "+
					"the allow-list is the OP's, not the client's", tc.declaredAlg)
			}
		})
	}
}
