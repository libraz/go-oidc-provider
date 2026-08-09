package jar_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/jar"
)

// staleIATClaims returns a claim set whose "iat" / "nbf" sit 30 minutes
// in the past while "exp" is still 5 minutes ahead. The shape is
// conformant under FAPI 2.0 Message Signing §5.6 (the object's whole
// validity window is well inside 60 minutes) and stale under the
// library default, so the two verifiers below disagree about it — which
// is the entire point of making the age cap configurable.
func staleIATClaims(now time.Time) map[string]any {
	minted := now.Add(-30 * time.Minute)
	c := happyClaims(now)
	c["iat"] = minted.Unix()
	c["nbf"] = minted.Unix()
	c["exp"] = now.Add(5 * time.Minute).Unix()
	return c
}

// TestVerify_DefaultMaxAgeRejectsThirtyMinuteOldIAT pins the unchanged
// default for deployments that declare no profile: an "iat" older than
// [jar.DefaultMaxAge] is refused even though "exp" has not passed.
func TestVerify_DefaultMaxAgeRejectsThirtyMinuteOldIAT(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	raw, keys := makeRequestObject(t, staleIATClaims(now))

	v, err := jar.NewVerifier(jar.VerifierConfig{
		Issuer:          testIssuer,
		Resolver:        &staticResolver{keys: keys},
		Clock:           fakeClock{now: now},
		AllowMissingJTI: true,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if _, err := v.Verify(context.Background(), raw, testClientID, newClient()); !errors.Is(err, jar.ErrExpired) {
		t.Fatalf("err=%v want ErrExpired (iat older than DefaultMaxAge)", err)
	}
}

// TestVerify_ProfileMaxAgeAcceptsThirtyMinuteOldIAT is the configured
// counterpart: with the 60-minute window a FAPI profile grants, the
// same request object verifies. Without a raised MaxAge the age check
// fires ahead of MaxLifetime and rejects an object the profile declares
// valid for another half hour.
func TestVerify_ProfileMaxAgeAcceptsThirtyMinuteOldIAT(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	raw, keys := makeRequestObject(t, staleIATClaims(now))

	v, err := jar.NewVerifier(jar.VerifierConfig{
		Issuer:          testIssuer,
		Resolver:        &staticResolver{keys: keys},
		Clock:           fakeClock{now: now},
		RequireNbf:      true,
		MaxAge:          60 * time.Minute,
		MaxLifetime:     60 * time.Minute,
		AllowMissingJTI: true,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if _, err := v.Verify(context.Background(), raw, testClientID, newClient()); err != nil {
		t.Fatalf("Verify rejected a request object inside the profile's 60-minute window: %v", err)
	}
}

// TestVerify_MaxAgeStillBoundsTheWindow keeps the raised cap from
// becoming "no cap at all": an "iat" beyond the configured age is
// refused whatever the lifetime allows.
func TestVerify_MaxAgeStillBoundsTheWindow(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	c := happyClaims(now)
	c["iat"] = now.Add(-90 * time.Minute).Unix()
	c["exp"] = now.Add(5 * time.Minute).Unix()
	raw, keys := makeRequestObject(t, c)

	v, err := jar.NewVerifier(jar.VerifierConfig{
		Issuer:          testIssuer,
		Resolver:        &staticResolver{keys: keys},
		Clock:           fakeClock{now: now},
		MaxAge:          60 * time.Minute,
		AllowMissingJTI: true,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if _, err := v.Verify(context.Background(), raw, testClientID, newClient()); !errors.Is(err, jar.ErrExpired) {
		t.Fatalf("err=%v want ErrExpired (iat older than the configured MaxAge)", err)
	}
}
