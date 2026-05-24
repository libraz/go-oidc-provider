package dpop_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/dpop"
	"github.com/libraz/go-oidc-provider/op/store"
)

// ttlJTIStore mirrors the production [op/storeadapter/inmem] semantics:
// an entry whose stored expiresAt is at or before "now" is treated as
// absent so a fresh Mark may succeed. The DPoP verifier's JTI expiry
// MUST therefore outlive the full iat acceptance window; otherwise a
// captured proof can replay at the upper boundary even though both
// submissions pass the iat gate.
type ttlJTIStore struct {
	mu    sync.Mutex
	clock func() time.Time
	m     map[string]time.Time
}

func newTTLJTIStore(clock func() time.Time) *ttlJTIStore {
	return &ttlJTIStore{clock: clock, m: map[string]time.Time{}}
}

func (s *ttlJTIStore) Mark(_ context.Context, jti string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.clock()
	if existing, ok := s.m[jti]; ok {
		// Matches inmem.isExpiredAt: now >= existing means expired.
		expired := !now.UTC().Before(existing.UTC())
		if !expired {
			return store.ErrAlreadyConsumed
		}
		delete(s.m, jti)
	}
	s.m[jti] = expiresAt
	return nil
}

func (s *ttlJTIStore) Has(_ context.Context, jti string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	existing, ok := s.m[jti]
	if !ok {
		return false, nil
	}
	if !s.clock().UTC().Before(existing.UTC()) {
		return false, nil
	}
	return true, nil
}

// movingClock is a [dpop.Clock] whose Now() value can be advanced
// between calls. The verifier reads Clock.Now() on every Verify, so
// advancing the clock between calls simulates the wall-clock progressing
// across an iat acceptance window.
type movingClock struct {
	mu sync.Mutex
	t  time.Time
}

func newMovingClock(start time.Time) *movingClock { return &movingClock{t: start} }

func (c *movingClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *movingClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// TestVerify_ReplayAtIatWindowUpperBoundary pins the contract: a proof
// captured at iat and replayed at the latest still-acceptable instant
// (now = iat + IatWindow) MUST surface ErrProofReplayed. The earlier
// implementation set the JTI expiry to iat + IatWindow, so at the
// upper boundary the store treated the entry as already expired and
// the attacker's Mark succeeded silently — the iat gate accepted the
// replay, the JTI gate failed open, and the proof passed.
func TestVerify_ReplayAtIatWindowUpperBoundary(t *testing.T) {
	t.Parallel()
	iat := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	key := newES256Key(t)
	raw := signProof(t, key, goodClaims(iat), "")
	clock := newMovingClock(iat)
	jtis := newTTLJTIStore(clock.Now)
	v, err := dpop.NewVerifier(dpop.VerifierConfig{
		JTIs:      jtis,
		Clock:     clock,
		IatWindow: time.Minute,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if _, err := v.Verify(context.Background(), dpop.VerifyInput{
		ProofHeader: raw,
		Method:      "POST",
		URL:         mustParseURL(t, "https://op.example/oidc/token"),
		TLS:         true,
	}); err != nil {
		t.Fatalf("first Verify: %v", err)
	}

	clock.advance(time.Minute) // now = iat + IatWindow (still inside the iat acceptance window)

	_, err = v.Verify(context.Background(), dpop.VerifyInput{
		ProofHeader: raw,
		Method:      "POST",
		URL:         mustParseURL(t, "https://op.example/oidc/token"),
		TLS:         true,
	})
	if !errors.Is(err, dpop.ErrProofReplayed) {
		t.Fatalf("replay at iat+IatWindow: err=%v want ErrProofReplayed", err)
	}
}

// TestVerify_ReplayAcrossFullIatWindow exercises the worst-case JTI
// lifetime: the first acceptance happens at the EARLIEST allowed
// instant (iat - IatWindow) and the replay arrives at the LATEST
// allowed instant (iat + IatWindow), a gap of 2 * IatWindow. The JTI
// entry must remain authoritative across the entire window.
func TestVerify_ReplayAcrossFullIatWindow(t *testing.T) {
	t.Parallel()
	iat := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	key := newES256Key(t)
	raw := signProof(t, key, goodClaims(iat), "")
	start := iat.Add(-time.Minute) // earliest accepted now
	clock := newMovingClock(start)
	jtis := newTTLJTIStore(clock.Now)
	v, err := dpop.NewVerifier(dpop.VerifierConfig{
		JTIs:      jtis,
		Clock:     clock,
		IatWindow: time.Minute,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if _, err := v.Verify(context.Background(), dpop.VerifyInput{
		ProofHeader: raw,
		Method:      "POST",
		URL:         mustParseURL(t, "https://op.example/oidc/token"),
		TLS:         true,
	}); err != nil {
		t.Fatalf("first Verify at iat-IatWindow: %v", err)
	}

	clock.advance(2 * time.Minute) // now = iat + IatWindow

	_, err = v.Verify(context.Background(), dpop.VerifyInput{
		ProofHeader: raw,
		Method:      "POST",
		URL:         mustParseURL(t, "https://op.example/oidc/token"),
		TLS:         true,
	})
	if !errors.Is(err, dpop.ErrProofReplayed) {
		t.Fatalf("replay across full iat window: err=%v want ErrProofReplayed", err)
	}
}

// TestVerify_JTIExpiresAfterIatWindowCloses pins the freed-entry
// contract: once the iat window can no longer accept the proof (now >
// iat + IatWindow), the JTI entry SHOULD be treated as collectable so
// long-lived processes do not retain consumed entries forever. The
// fix relaxes "expires at iat + IatWindow" to "expires at iat +
// 2*IatWindow", so the entry is releasable as soon as the iat gate
// would reject any further replay attempt — not a moment sooner.
func TestVerify_JTIExpiresAfterIatWindowCloses(t *testing.T) {
	t.Parallel()
	iat := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	key := newES256Key(t)
	raw := signProof(t, key, goodClaims(iat), "")
	clock := newMovingClock(iat)
	jtis := newTTLJTIStore(clock.Now)
	v, err := dpop.NewVerifier(dpop.VerifierConfig{
		JTIs:      jtis,
		Clock:     clock,
		IatWindow: time.Minute,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if _, err := v.Verify(context.Background(), dpop.VerifyInput{
		ProofHeader: raw,
		Method:      "POST",
		URL:         mustParseURL(t, "https://op.example/oidc/token"),
		TLS:         true,
	}); err != nil {
		t.Fatalf("first Verify: %v", err)
	}

	// One nanosecond past the latest acceptable replay window the iat
	// gate is the front-line defence. The JTI entry MAY be present or
	// absent at this point; the test only insists Has() does not lie
	// about a still-live entry.
	clock.advance(2*time.Minute + time.Nanosecond)
	if got, err := jtis.Has(context.Background(), "jti-1"); err != nil {
		t.Fatalf("Has: %v", err)
	} else if got {
		t.Fatalf("Has(jti-1) past 2*IatWindow = true; want store to treat the entry as collectable")
	}
}
