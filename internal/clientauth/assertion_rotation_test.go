package clientauth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/clientauth"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// rotatingResolver models a jwks_uri-backed resolver whose cached keyset
// lags a key rotation: JWKS returns the stale set, and RefreshJWKS (the
// cache-bypassing refetch) returns the current set. It counts refetches
// so a test can assert the retry path fires exactly when it should.
type rotatingResolver struct {
	stale     *josev4.JSONWebKeySet
	fresh     *josev4.JSONWebKeySet
	refetch   *int
	failFresh error
}

func (r rotatingResolver) JWKS(_ context.Context, _ string) (*josev4.JSONWebKeySet, error) {
	return r.stale, nil
}

func (r rotatingResolver) RefreshJWKS(_ context.Context, _ string) (*josev4.JSONWebKeySet, error) {
	*r.refetch++
	if r.failFresh != nil {
		return nil, r.failFresh
	}
	return r.fresh, nil
}

func rsaJWKSet(pub *rsa.PublicKey, kid string) *josev4.JSONWebKeySet {
	return &josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{{
		Key: pub, KeyID: kid, Algorithm: string(josev4.RS256), Use: "sig",
	}}}
}

func rotationVerifier(tb testing.TB, resolver clientauth.JWKSResolver, aud string, now time.Time) *clientauth.PrivateKeyJWTVerifier {
	tb.Helper()
	return &clientauth.PrivateKeyJWTVerifier{
		Resolver: resolver,
		JTIStore: inmem.New(inmem.WithClock(fixedClock{now: now})).ConsumedJTIs(),
		Audience: aud,
		Clock:    fixedClock{now: now}.Now,
	}
}

// TestPrivateKeyJWTVerifier_RotatedKeyRefetched proves the RP-key-rotation
// recovery path: an assertion signed with a key whose kid is absent from
// the cached keyset authenticates after a single cache-bypassing refetch
// surfaces the rotated-in key. This is the OFCS
// oidcc-refresh-token-rp-key-rotation scenario in miniature.
func TestPrivateKeyJWTVerifier_RotatedKeyRefetched(t *testing.T) {
	t.Parallel()

	const aud = "https://op.test/oidc/token"
	oldKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey old: %v", err)
	}
	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey new: %v", err)
	}
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)

	refetch := 0
	resolver := rotatingResolver{
		stale:   rsaJWKSet(&oldKey.PublicKey, "rp-key-1"),
		fresh:   rsaJWKSet(&newKey.PublicKey, "rp-key-2"),
		refetch: &refetch,
	}
	v := rotationVerifier(t, resolver, aud, now)

	// The assertion is signed with the rotated-in key (kid rp-key-2),
	// which the stale keyset does not carry.
	assertion := signRSAAssertion(t, newKey, "rp-key-2", map[string]any{
		"iss": "client-1", "sub": "client-1", "aud": aud, "jti": "j-rot-ok",
		"iat": now.Add(-30 * time.Second).Unix(), "exp": now.Add(2 * time.Minute).Unix(),
	})
	if err := v.Verify(context.Background(), "client-1", assertion); err != nil {
		t.Fatalf("Verify after rotation: %v", err)
	}
	if refetch != 1 {
		t.Errorf("refetch count=%d, want 1", refetch)
	}
}

// TestPrivateKeyJWTVerifier_PresentKidDoesNotRefetch proves the refetch is
// gated on a kid miss: a bad signature under a kid that IS in the cached
// keyset is rejected without a wasted (and potentially amplifying)
// refetch. Only a genuinely-unknown kid — the rotation signal — triggers
// the network round-trip.
func TestPrivateKeyJWTVerifier_PresentKidDoesNotRefetch(t *testing.T) {
	t.Parallel()

	const aud = "https://op.test/oidc/token"
	cachedKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey cached: %v", err)
	}
	imposter, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey imposter: %v", err)
	}
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)

	refetch := 0
	resolver := rotatingResolver{
		stale:   rsaJWKSet(&cachedKey.PublicKey, "rp-key-1"),
		fresh:   rsaJWKSet(&imposter.PublicKey, "rp-key-1"),
		refetch: &refetch,
	}
	v := rotationVerifier(t, resolver, aud, now)

	// Signed by a different key but reusing the cached kid: the signature
	// does not verify and the kid is present, so this must NOT refetch.
	assertion := signRSAAssertion(t, imposter, "rp-key-1", map[string]any{
		"iss": "client-1", "sub": "client-1", "aud": aud, "jti": "j-imposter",
		"iat": now.Add(-30 * time.Second).Unix(), "exp": now.Add(2 * time.Minute).Unix(),
	})
	if err := v.Verify(context.Background(), "client-1", assertion); err == nil {
		t.Fatal("Verify accepted a forged assertion")
	}
	if refetch != 0 {
		t.Errorf("refetch count=%d, want 0 (kid was present)", refetch)
	}
}

// TestPrivateKeyJWTVerifier_RefetchStillMissesRejects proves the retry is
// bounded: when even the freshly-fetched keyset lacks a verifying key the
// assertion is rejected rather than looping.
func TestPrivateKeyJWTVerifier_RefetchStillMissesRejects(t *testing.T) {
	t.Parallel()

	const aud = "https://op.test/oidc/token"
	oldKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey old: %v", err)
	}
	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey new: %v", err)
	}
	unrelated, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey unrelated: %v", err)
	}
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)

	refetch := 0
	resolver := rotatingResolver{
		stale:   rsaJWKSet(&oldKey.PublicKey, "rp-key-1"),
		fresh:   rsaJWKSet(&unrelated.PublicKey, "rp-key-9"),
		refetch: &refetch,
	}
	v := rotationVerifier(t, resolver, aud, now)

	assertion := signRSAAssertion(t, newKey, "rp-key-2", map[string]any{
		"iss": "client-1", "sub": "client-1", "aud": aud, "jti": "j-still-miss",
		"iat": now.Add(-30 * time.Second).Unix(), "exp": now.Add(2 * time.Minute).Unix(),
	})
	if err := v.Verify(context.Background(), "client-1", assertion); err == nil {
		t.Fatal("Verify accepted an assertion no fetched key covers")
	}
	if refetch != 1 {
		t.Errorf("refetch count=%d, want 1", refetch)
	}
}
