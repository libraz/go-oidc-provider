package introspectendpoint

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
)

// jtiProbeIssuer is the issuer the probe tokens below are signed for.
const jtiProbeIssuer = "https://op.jti-probe.invalid"

// signJTIProbeToken mints a JWT access token for the strategy probes,
// with the jti claim under the caller's control.
func signJTIProbeToken(tb testing.TB, key tokens.SigningKey, jti string) string {
	tb.Helper()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	raw, err := tokens.SignAccessToken(key, tokens.AccessTokenClaims{
		Issuer:    jtiProbeIssuer,
		Subject:   "user-1",
		Audience:  []string{jtiProbeIssuer},
		ClientID:  "client-1",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Hour).Unix(),
		JTI:       jti,
	})
	if err != nil {
		tb.Fatalf("SignAccessToken: %v", err)
	}
	return raw
}

// newJTIProbeKeys returns a keyset plus the matching signer.
func newJTIProbeKeys(tb testing.TB) (*keys.Set, tokens.SigningKey) {
	tb.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("generate key: %v", err)
	}
	set, err := keys.NewSet([]keys.Entry{{KeyID: jtiProbeKeyID, Signer: priv}})
	if err != nil {
		tb.Fatalf("keys.NewSet: %v", err)
	}
	return set, tokens.SigningKey{KeyID: jtiProbeKeyID, Signer: priv}
}

const jtiProbeKeyID = "jti-probe-1"

// TestNewAccessTokenVerifier_RequiresJTIByStrategy pins the wiring this
// endpoint applies to the shared verifier: the jti requirement follows
// the configured revocation strategy rather than being left at its zero
// value.
//
// The check matters because a verifier constructed without it accepts a
// token the revocation probe cannot answer for — the registry lookup is
// keyed on jti, and the tombstone path reaches a grantless token only
// through the jti denylist row — and the probe reports an unanswerable
// question as "not revoked".
func TestNewAccessTokenVerifier_RequiresJTIByStrategy(t *testing.T) {
	t.Parallel()

	keySet, signer := newJTIProbeKeys(t)
	jtiLess := signJTIProbeToken(t, signer, "")
	normal := signJTIProbeToken(t, signer, "at-1")

	cases := []struct {
		name       string
		strategy   store.AccessTokenRevocationStrategy
		rejectsJTI bool
	}{
		{"jti_registry", store.RevocationStrategyJTIRegistry, true},
		{"grant_tombstone", store.RevocationStrategyGrantTombstone, true},
		{"none", store.RevocationStrategyNone, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			v := newAccessTokenVerifier(Deps{
				Keys:               keySet,
				Issuer:             jtiProbeIssuer,
				Clock:              jtiProbeClock{},
				RevocationStrategy: tc.strategy,
			})
			_, _, err := v.Verify(context.Background(), jtiLess)
			switch {
			case tc.rejectsJTI && err == nil:
				t.Errorf("a jti-less token verified under %v; revocation cannot reach it, "+
					"so it would read as live until exp", tc.strategy)
			case !tc.rejectsJTI && err != nil:
				t.Errorf("a jti-less token was rejected under %v, which consults no per-token "+
					"state at all: %v", tc.strategy, err)
			}
			if _, _, verr := v.Verify(context.Background(), normal); verr != nil {
				t.Errorf("a normally-minted token was rejected under %v: %v", tc.strategy, verr)
			}
		})
	}
}

// jtiProbeClock pins the verifier's clock to the token's validity
// window so the probes exercise the jti branch rather than expiry.
type jtiProbeClock struct{}

func (jtiProbeClock) Now() time.Time {
	return time.Date(2026, 4, 26, 12, 30, 0, 0, time.UTC)
}
