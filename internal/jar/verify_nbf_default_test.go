package jar_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/jar"
)

// TestVerify_RequireNbfRejectsMissing pins the FAPI 2.0 Message
// Signing §5.6 stance: when a profile (FAPI) flips
// [VerifierConfig.RequireNbf] to true, request objects that omit
// "nbf" are rejected. Non-FAPI deployments retain the RFC 9101 §6.1
// "nbf optional" default and are exercised by [TestVerify_NoNbf]
// below.
func TestVerify_RequireNbfRejectsMissing(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	c := happyClaims(now)
	delete(c, "nbf") // happyClaims does not carry nbf in the first place
	raw, keys := makeRequestObject(t, c)

	v, err := jar.NewVerifier(jar.VerifierConfig{
		Issuer:          testIssuer,
		Resolver:        &staticResolver{keys: keys},
		Clock:           fakeClock{now: now},
		RequireNbf:      true,
		AllowMissingJTI: true,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	_, err = v.Verify(context.Background(), raw, testClientID, newClient())
	if !errors.Is(err, jar.ErrNotYetValid) {
		t.Fatalf("err=%v want ErrNotYetValid (RequireNbf=true)", err)
	}
}

// TestVerify_AllowMissingNbfDominatesRequireNbf ensures that when
// both flags are set, the explicit opt-out wins so an embedder that
// turned RequireNbf on at the profile layer can punch a hole for a
// specific client without rebuilding the verifier.
func TestVerify_AllowMissingNbfDominatesRequireNbf(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	c := happyClaims(now) // no nbf
	raw, keys := makeRequestObject(t, c)

	v, err := jar.NewVerifier(jar.VerifierConfig{
		Issuer:          testIssuer,
		Resolver:        &staticResolver{keys: keys},
		Clock:           fakeClock{now: now},
		RequireNbf:      true,
		AllowMissingNbf: true,
		AllowMissingJTI: true,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if _, err := v.Verify(context.Background(), raw, testClientID, newClient()); err != nil {
		t.Fatalf("Verify must accept nbf-less request when AllowMissingNbf wins: %v", err)
	}
}
