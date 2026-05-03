// White-box tests against the package-private cache. Living in the
// same package avoids exporting the cache solely so tests can reach
// it.
//
//nolint:testpackage // intentional white-box test for unexported helpers.
package clientencjwks

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/timex"
)

// movableClock is a [timex.Clock] whose Now reading callers can
// shift. Tests use it to drive the cache's TTL expiry without
// sleeping.
type movableClock struct {
	now time.Time
}

func (m *movableClock) Now() time.Time { return m.now }

var _ timex.Clock = (*movableClock)(nil)

// fakeJWKS returns a single-entry JWKS suitable for cache tests. The
// content of the key does not matter; only the pointer identity does
// because the cache returns whatever was stored verbatim.
func fakeJWKS(t *testing.T) *josev4.JSONWebKeySet {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return &josev4.JSONWebKeySet{
		Keys: []josev4.JSONWebKey{{
			Key:   &priv.PublicKey,
			KeyID: "k1",
			Use:   "enc",
		}},
	}
}

func TestJWKSCache_HitWithinTTL(t *testing.T) {
	t.Parallel()

	clock := &movableClock{now: time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)}
	c := newJWKSCache(clock, 60*time.Second)

	keys := fakeJWKS(t)
	c.put("https://rp.example/jwks", keys)

	clock.now = clock.now.Add(30 * time.Second)
	got, ok := c.get("https://rp.example/jwks")
	if !ok {
		t.Fatal("get returned ok=false within TTL")
	}
	if got != keys {
		t.Errorf("get returned different pointer; want cached value")
	}
}

func TestJWKSCache_MissAfterTTL(t *testing.T) {
	t.Parallel()

	clock := &movableClock{now: time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)}
	c := newJWKSCache(clock, 60*time.Second)

	c.put("https://rp.example/jwks", fakeJWKS(t))

	// Step past the TTL boundary.
	clock.now = clock.now.Add(120 * time.Second)
	if _, ok := c.get("https://rp.example/jwks"); ok {
		t.Fatal("get returned ok=true after TTL expired")
	}
}

func TestJWKSCache_MissOnUnknownURL(t *testing.T) {
	t.Parallel()

	c := newJWKSCache(timex.SystemClock, time.Minute)
	if _, ok := c.get("https://other.example/jwks"); ok {
		t.Fatal("get returned ok=true for unknown URL")
	}
}

func TestJWKSCache_PutOverwrites(t *testing.T) {
	t.Parallel()

	clock := &movableClock{now: time.Date(2026, 5, 4, 12, 0, 0, 0, time.UTC)}
	c := newJWKSCache(clock, 60*time.Second)

	first := fakeJWKS(t)
	second := fakeJWKS(t)
	c.put("https://rp.example/jwks", first)
	c.put("https://rp.example/jwks", second)

	got, ok := c.get("https://rp.example/jwks")
	if !ok {
		t.Fatal("get returned ok=false after put")
	}
	if got != second {
		t.Errorf("get returned the first put; want the second (overwrite)")
	}
}

func TestJWKSCache_NilClockFallsBackToSystem(t *testing.T) {
	t.Parallel()

	c := newJWKSCache(nil, time.Minute)
	if c.clock == nil {
		t.Fatal("clock is nil after nil-clock construction")
	}
}

func TestJWKSCache_ZeroTTLFallsBackToDefault(t *testing.T) {
	t.Parallel()

	c := newJWKSCache(timex.SystemClock, 0)
	if c.ttl != defaultJWKSCacheTTL {
		t.Errorf("ttl=%v want defaultJWKSCacheTTL=%v", c.ttl, defaultJWKSCacheTTL)
	}
}
