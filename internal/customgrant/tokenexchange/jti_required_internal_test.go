package tokenexchange

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/store"
)

// jtiProbeIssuer is the issuer the probe tokens below are signed for.
const jtiProbeIssuer = "https://op.jti-probe.invalid"

const jtiProbeKeyID = "jti-probe-1"

// jtiProbeClock pins the handler's clock inside the probe tokens'
// validity window so the probes exercise the jti branch, not expiry.
type jtiProbeClock struct{}

func (jtiProbeClock) Now() time.Time {
	return time.Date(2026, 4, 26, 12, 30, 0, 0, time.UTC)
}

// signJTIProbeToken mints a JWT access token with the jti under the
// caller's control.
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

// newJTIProbeHandler builds a handler on the requested strategy plus
// the signer whose tokens it will accept.
func newJTIProbeHandler(tb testing.TB, strategy store.AccessTokenRevocationStrategy) (*Handler, tokens.SigningKey) {
	tb.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("generate key: %v", err)
	}
	set, err := keys.NewSet([]keys.Entry{{KeyID: jtiProbeKeyID, Signer: priv}})
	if err != nil {
		tb.Fatalf("keys.NewSet: %v", err)
	}
	h, err := New(Config{
		Policy: func(context.Context, RequestView) (*Decision, error) {
			return &Decision{}, nil
		},
		Issuer:             jtiProbeIssuer,
		Keys:               set,
		RevocationStrategy: strategy,
		Clock:              jtiProbeClock{},
	})
	if err != nil {
		tb.Fatalf("New: %v", err)
	}
	return h, tokens.SigningKey{KeyID: jtiProbeKeyID, Signer: priv}
}

// TestLookupJWT_RequiresJTIByStrategy pins the token-exchange face of
// the same floor the other access-token surfaces enforce: a subject
// token carrying no jti is refused whenever the configured strategy has
// a revocation path that keys on it.
//
// Token exchange is the surface where accepting one matters most: the
// unrevocable token is not merely read, it is traded for a fresh one,
// so a single missed check converts a token revocation cannot reach
// into a whole new grant.
func TestLookupJWT_RequiresJTIByStrategy(t *testing.T) {
	t.Parallel()

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

			h, signer := newJTIProbeHandler(t, tc.strategy)
			_, err := h.lookupAccessToken(context.Background(), signJTIProbeToken(t, signer, ""))
			switch {
			case tc.rejectsJTI && !errors.Is(err, errTokenInvalid):
				t.Errorf("a jti-less token was accepted for exchange under %v (err=%v); "+
					"revocation cannot reach it, so it would trade for a fresh grant until exp",
					tc.strategy, err)
			case !tc.rejectsJTI && err != nil:
				t.Errorf("a jti-less token was rejected under %v, which consults no per-token "+
					"state at all: %v", tc.strategy, err)
			}
			if _, verr := h.lookupAccessToken(context.Background(), signJTIProbeToken(t, signer, "at-1")); verr != nil {
				t.Errorf("a normally-minted token was rejected under %v: %v", tc.strategy, verr)
			}
		})
	}
}
