package tokens_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/tokens"
)

// advisoryClock is a mutable clock safe for use from one test goroutine.
type advisoryClock struct{ ns atomic.Int64 }

func newAdvisoryClock(t time.Time) *advisoryClock {
	c := &advisoryClock{}
	c.ns.Store(t.UnixNano())
	return c
}

func (c *advisoryClock) Now() time.Time      { return time.Unix(0, c.ns.Load()).UTC() }
func (c *advisoryClock) Set(t time.Time)     { c.ns.Store(t.UnixNano()) }
func (c *advisoryClock) Add(d time.Duration) { c.ns.Add(int64(d)) }

func advisoryClaims(now time.Time) tokens.AccessTokenClaims {
	return tokens.AccessTokenClaims{
		Issuer:    "https://op.example.com",
		Subject:   "user-1",
		Audience:  []string{"https://api.example.com"},
		ClientID:  "client-1",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(time.Minute).Unix(),
		JTI:       "at-advisory",
	}
}

// TestVerify_RejectsNonObjectPayloads pins that a correctly signed JWS whose
// payload is not a JSON object never yields claims.
//
// Tracks: CVE-2026-107723 (fast-jwt — claim validation silently skipped when
// the payload was a JSON array)
func TestVerify_RejectsNonObjectPayloads(t *testing.T) {
	t.Parallel()

	set, entry := mustKeySet(t, "kid-1")
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	v := &tokens.AccessTokenVerifier{Keys: set, Issuer: "https://op.example.com", Clock: fakeClock{now: now}}

	for name, payload := range map[string]any{
		"array":  []any{},
		"null":   nil,
		"string": "s",
		"number": 1,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			raw := signedRawAnyPayload(t, entry, payload)
			got, _, err := v.Verify(context.Background(), raw)
			if err == nil || got != nil {
				t.Fatalf("accepted payload %s: claims=%+v err=%v", name, got, err)
			}
			if !errors.Is(err, tokens.ErrAccessTokenMalformed) {
				t.Fatalf("err=%v want ErrAccessTokenMalformed", err)
			}
		})
	}
}

// TestVerify_ExpiryTracksClockAcrossCalls pins that the same raw token is
// re-evaluated against the live clock on every Verify call: accepted at t0,
// expired once the clock passes exp plus the leeway.
//
// Tracks: CVE-2026-107719 (fast-jwt — verifier cache kept accepting an
// expired JWT that lacked iat)
func TestVerify_ExpiryTracksClockAcrossCalls(t *testing.T) {
	t.Parallel()

	set, entry := mustKeySet(t, "kid-1")
	t0 := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	claims := advisoryClaims(t0)
	raw := signed(t, entry, claims)

	clk := newAdvisoryClock(t0)
	v := &tokens.AccessTokenVerifier{
		Keys: set, Issuer: claims.Issuer, Clock: clk, Leeway: tokens.DefaultLeeway,
	}
	if _, _, err := v.Verify(context.Background(), raw); err != nil {
		t.Fatalf("Verify at t0: %v", err)
	}
	// Still inside the window; a second call must also pass.
	if _, _, err := v.Verify(context.Background(), raw); err != nil {
		t.Fatalf("repeat Verify at t0: %v", err)
	}

	clk.Set(time.Unix(claims.ExpiresAt, 0).Add(tokens.DefaultLeeway + time.Second))
	if _, _, err := v.Verify(context.Background(), raw); !errors.Is(err, tokens.ErrAccessTokenExpired) {
		t.Fatalf("Verify past exp+leeway: err=%v want ErrAccessTokenExpired", err)
	}
}

// TestVerify_LeewayIsBoundedConstant pins the exp tolerance at exactly
// DefaultLeeway: one second inside it is accepted, one second beyond it is
// expired, so the skew can never silently become unbounded.
//
// Tracks: CVE-2026-107721 (fast-jwt — clockTolerance: Infinity disabled the
// exp/nbf checks)
func TestVerify_LeewayIsBoundedConstant(t *testing.T) {
	t.Parallel()

	set, entry := mustKeySet(t, "kid-1")
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name    string
		age     time.Duration // how long ago exp was
		wantErr error
	}{
		{"expired beyond leeway", tokens.DefaultLeeway + time.Second, tokens.ErrAccessTokenExpired},
		{"expired within leeway", tokens.DefaultLeeway - time.Second, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			claims := advisoryClaims(now.Add(-time.Hour))
			claims.ExpiresAt = now.Add(-tc.age).Unix()
			raw := signed(t, entry, claims)
			v := &tokens.AccessTokenVerifier{
				Keys: set, Issuer: claims.Issuer, Clock: fakeClock{now: now}, Leeway: tokens.DefaultLeeway,
			}
			_, _, err := v.Verify(context.Background(), raw)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("Verify: %v", err)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err=%v want %v", err, tc.wantErr)
			}
		})
	}
}

// signedRawAnyPayload signs an arbitrary JSON value as an at+jwt payload.
func signedRawAnyPayload(tb testing.TB, entry keys.Entry, payload any) string {
	tb.Helper()
	signer, err := josev4.NewSigner(
		josev4.SigningKey{Algorithm: josev4.ES256, Key: entry.Signer},
		(&josev4.SignerOptions{}).WithHeader("kid", entry.KeyID).WithType("at+jwt"),
	)
	if err != nil {
		tb.Fatalf("NewSigner: %v", err)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		tb.Fatalf("Marshal: %v", err)
	}
	obj, err := signer.Sign(body)
	if err != nil {
		tb.Fatalf("Sign: %v", err)
	}
	raw, err := obj.CompactSerialize()
	if err != nil {
		tb.Fatalf("CompactSerialize: %v", err)
	}
	return raw
}
