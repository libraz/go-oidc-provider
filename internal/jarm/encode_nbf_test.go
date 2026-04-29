package jarm_test

import (
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/jarm"
)

// TestSigner_StampsNbf closes the L-JARM-NBF gap: every JARM response
// MUST carry an "nbf" claim equal to "iat" so consumers running under
// FAPI 2.0 Message Signing §5.6 can enforce a uniform nbf-or-fail
// rule on response objects.
func TestSigner_StampsNbf(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	signer, err := jarm.NewSigner(jarm.SignerConfig{
		Key:    generateTestSigningKey(t),
		Issuer: "https://op.example.com",
		Clock:  fixedClock{now: now},
		Expiry: 60 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	out, err := signer.SignDefault(jarm.Payload{
		Audience: "client-1",
		Code:     "code-abc",
	})
	if err != nil {
		t.Fatalf("SignDefault: %v", err)
	}
	claims := encodedClaims(t, out)
	nbf, ok := claims["nbf"].(float64)
	if !ok {
		t.Fatalf("nbf not numeric: %T (%v)", claims["nbf"], claims["nbf"])
	}
	iat, _ := claims["iat"].(float64)
	if int64(nbf) != int64(iat) {
		t.Errorf("nbf=%d want %d (must equal iat)", int64(nbf), int64(iat))
	}
	if int64(nbf) != now.Unix() {
		t.Errorf("nbf=%d want %d (clock anchor)", int64(nbf), now.Unix())
	}
}
