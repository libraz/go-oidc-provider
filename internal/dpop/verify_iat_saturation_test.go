package dpop_test

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/dpop"
)

// The iat freshness gate is the only thing standing between a captured
// DPoP proof and unlimited reuse, and the value it compares is supplied
// by the client. These tests pin that no int64 an attacker can put in
// "iat" passes the gate, and that a proof which does pass cannot decide
// how long the OP keeps its replay marker.

// TestVerify_FarFutureIatIsRejected walks the iat values that break a
// difference-based window check: a timestamp beyond time.Duration's
// range makes now.Sub(iat) saturate at math.MinInt64, and negating that
// wraps to itself — so the "distance" compares as smaller than any
// window and the proof is admitted. Every one of these must be refused
// in both directions.
func TestVerify_FarFutureIatIsRejected(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name string
		iat  int64
	}{
		{"year 9999", 253402300799},
		{"saturation threshold", now.Unix() + int64(math.MaxInt64/int64(time.Second)) + 1},
		{"max int64", math.MaxInt64},
		{"min int64", math.MinInt64},
		{"far past", now.Unix() - 253402300799},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			key := newES256Key(t)
			claims := goodClaims(now)
			claims["iat"] = tc.iat
			raw := signProof(t, key, claims, "")

			jtis := newMemJTIStore()
			v, err := dpop.NewVerifier(dpop.VerifierConfig{
				JTIs:      jtis,
				Clock:     fixedClock{now: now},
				IatWindow: time.Minute,
			})
			if err != nil {
				t.Fatalf("NewVerifier: %v", err)
			}
			_, err = v.Verify(context.Background(), dpop.VerifyInput{
				ProofHeader: raw,
				Method:      "POST",
				URL:         mustParseURL(t, "https://op.example/oidc/token"),
				TLS:         true,
			})
			if !errors.Is(err, dpop.ErrProofIatWindow) {
				t.Fatalf("iat=%d: err=%v want ErrProofIatWindow", tc.iat, err)
			}
			if jtis.len() != 0 {
				t.Errorf("iat=%d: a refused proof wrote %d replay entries; the table must stay untouched",
					tc.iat, jtis.len())
			}
		})
	}
}

// TestVerify_ReplayMarkerLifetimeIsBounded pins the retention ceiling:
// however a proof's iat is placed inside the accepted window, its
// replay marker never outlives now + IatWindow + 2*IatWindow. Without
// the bound, retention is whatever the client wrote in "iat".
func TestVerify_ReplayMarkerLifetimeIsBounded(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	const window = time.Minute

	// The latest iat the gate accepts, which is also the latest marker
	// the OP may legitimately hold.
	key := newES256Key(t)
	claims := goodClaims(now.Add(window))
	raw := signProof(t, key, claims, "")

	jtis := newMemJTIStore()
	v, err := dpop.NewVerifier(dpop.VerifierConfig{
		JTIs:      jtis,
		Clock:     fixedClock{now: now},
		IatWindow: window,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	result, err := v.Verify(context.Background(), dpop.VerifyInput{
		ProofHeader: raw,
		Method:      "POST",
		URL:         mustParseURL(t, "https://op.example/oidc/token"),
		TLS:         true,
	})
	if err != nil {
		t.Fatalf("Verify at iat=now+window: %v", err)
	}
	ceiling := now.Add(window + 2*window)
	got := jtis.expiryOf("dpop:" + result.JKT + ":" + result.JTI)
	if got.IsZero() {
		t.Fatal("no replay marker was written for an accepted proof")
	}
	if got.After(ceiling) {
		t.Errorf("replay marker expires %v, past the ceiling %v; the client's iat is deciding retention",
			got, ceiling)
	}
}
