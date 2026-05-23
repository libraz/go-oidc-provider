package jar_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/jar"
	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// jtiKey returns a fresh ES256 keypair plus a single-key JWKS that
// verifies signatures from it. The helper lets a single test sign
// multiple distinct request objects with the same key so the
// staticResolver can serve all of them through one keyset.
func jtiKey(t *testing.T, kid string) (*ecdsa.PrivateKey, *josev4.JSONWebKeySet) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub := josev4.JSONWebKey{
		Key:       &priv.PublicKey,
		KeyID:     kid,
		Algorithm: string(josev4.ES256),
		Use:       "sig",
	}
	return priv, &josev4.JSONWebKeySet{Keys: []josev4.JSONWebKey{pub}}
}

// TestVerify_RejectsMissingJTI pins the RFC 9101 §10.8 default: a
// request object that omits "jti" is rejected when the verifier was
// constructed with a non-nil JTIs store and AllowMissingJTI is left
// unset. The case mirrors the runtime configuration the op layer
// produces from store.ConsumedJTIs().
func TestVerify_RejectsMissingJTI(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	priv, keys := jtiKey(t, testKID)
	c := happyClaims(now)
	c["nbf"] = now.Unix()
	delete(c, "jti")
	raw := signClaims(t, priv, testKID, c, josev4.ES256)

	v, err := jar.NewVerifier(jar.VerifierConfig{
		Issuer:   testIssuer,
		Resolver: &staticResolver{keys: keys},
		Clock:    fakeClock{now: now},
		JTIs:     inmem.New(inmem.WithClock(fakeClock{now: now})).ConsumedJTIs(),
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	_, gotErr := v.Verify(context.Background(), raw, testClientID, newClient())
	if !errors.Is(gotErr, jar.ErrJTIMissing) {
		t.Fatalf("err=%v want ErrJTIMissing", gotErr)
	}
}

// TestVerify_RejectsReplayedJTI asserts the §10.8 floor: a second
// Verify with the same jti returns ErrJTIReplayed even when every
// other claim is fresh.
func TestVerify_RejectsReplayedJTI(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	jtis := inmem.New(inmem.WithClock(fakeClock{now: now})).ConsumedJTIs()
	priv, keys := jtiKey(t, testKID)

	c1 := happyClaims(now)
	c1["nbf"] = now.Unix()
	c1["jti"] = "shared-jti-001"
	raw1 := signClaims(t, priv, testKID, c1, josev4.ES256)

	v, err := jar.NewVerifier(jar.VerifierConfig{
		Issuer:   testIssuer,
		Resolver: &staticResolver{keys: keys},
		Clock:    fakeClock{now: now},
		JTIs:     jtis,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}

	if _, err := v.Verify(context.Background(), raw1, testClientID, newClient()); err != nil {
		t.Fatalf("first Verify must succeed: %v", err)
	}

	// Replay the same payload byte-equal: the consumed-jti gate must
	// flag it.
	if _, err := v.Verify(context.Background(), raw1, testClientID, newClient()); !errors.Is(err, jar.ErrJTIReplayed) {
		t.Fatalf("err=%v want ErrJTIReplayed (byte-equal replay)", err)
	}

	// A freshly minted second object that re-uses the same jti also
	// must fail; the signature differs but the gate fires regardless.
	c2 := happyClaims(now)
	c2["nbf"] = now.Unix()
	c2["jti"] = "shared-jti-001"
	c2["state"] = "second"
	raw2 := signClaims(t, priv, testKID, c2, josev4.ES256)
	if _, err := v.Verify(context.Background(), raw2, testClientID, newClient()); !errors.Is(err, jar.ErrJTIReplayed) {
		t.Fatalf("err=%v want ErrJTIReplayed (re-used jti)", err)
	}
}

// TestVerify_AllowsDistinctJTIs is the positive companion to
// [TestVerify_RejectsReplayedJTI]: two objects whose jti differs go
// through, even when the rest of the claim bag is identical.
func TestVerify_AllowsDistinctJTIs(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	jtis := inmem.New(inmem.WithClock(fakeClock{now: now})).ConsumedJTIs()
	priv, keys := jtiKey(t, testKID)

	c1 := happyClaims(now)
	c1["nbf"] = now.Unix()
	c1["jti"] = "distinct-jti-A"
	raw1 := signClaims(t, priv, testKID, c1, josev4.ES256)

	c2 := happyClaims(now)
	c2["nbf"] = now.Unix()
	c2["jti"] = "distinct-jti-B"
	raw2 := signClaims(t, priv, testKID, c2, josev4.ES256)

	v, err := jar.NewVerifier(jar.VerifierConfig{
		Issuer:   testIssuer,
		Resolver: &staticResolver{keys: keys},
		Clock:    fakeClock{now: now},
		JTIs:     jtis,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if _, err := v.Verify(context.Background(), raw1, testClientID, newClient()); err != nil {
		t.Fatalf("Verify(A): %v", err)
	}
	if _, err := v.Verify(context.Background(), raw2, testClientID, newClient()); err != nil {
		t.Fatalf("Verify(B): %v", err)
	}
}

// TestVerify_ScopesJTIPerClient asserts the namespace separation in
// the consumed-jti key. Two different clients minting the same jti
// value MUST NOT collide — the gate includes the client_id in the
// replay-store key, so the second client's request object passes despite sharing the
// literal jti string with the first.
func TestVerify_ScopesJTIPerClient(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	jtis := inmem.New(inmem.WithClock(fakeClock{now: now})).ConsumedJTIs()
	priv, keys := jtiKey(t, testKID)

	const otherClientID = "rp-other"

	c1 := happyClaims(now)
	c1["nbf"] = now.Unix()
	c1["jti"] = "shared"
	raw1 := signClaims(t, priv, testKID, c1, josev4.ES256)

	c2 := happyClaims(now)
	c2["nbf"] = now.Unix()
	c2["jti"] = "shared"
	c2["iss"] = otherClientID
	c2["client_id"] = otherClientID
	raw2 := signClaims(t, priv, testKID, c2, josev4.ES256)

	v, err := jar.NewVerifier(jar.VerifierConfig{
		Issuer:   testIssuer,
		Resolver: &staticResolver{keys: keys},
		Clock:    fakeClock{now: now},
		JTIs:     jtis,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if _, err := v.Verify(context.Background(), raw1, testClientID, newClient()); err != nil {
		t.Fatalf("first Verify: %v", err)
	}
	other := newClient()
	other.ID = otherClientID
	if _, err := v.Verify(context.Background(), raw2, otherClientID, other); err != nil {
		t.Fatalf("second client must not collide on shared jti: %v", err)
	}
}

func TestVerify_ScopesJTIPerEndpointUse(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	jtis := inmem.New(inmem.WithClock(fakeClock{now: now})).ConsumedJTIs()
	priv, keys := jtiKey(t, testKID)

	c := happyClaims(now)
	c["nbf"] = now.Unix()
	c["jti"] = "shared-across-endpoints"
	raw := signClaims(t, priv, testKID, c, josev4.ES256)

	v, err := jar.NewVerifier(jar.VerifierConfig{
		Issuer:   testIssuer,
		Resolver: &staticResolver{keys: keys},
		Clock:    fakeClock{now: now},
		JTIs:     jtis,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if _, err := v.Verify(context.Background(), raw, testClientID, newClient()); err != nil {
		t.Fatalf("authorize Verify: %v", err)
	}
	if _, err := v.VerifyCIBA(context.Background(), raw, testClientID, newClient()); err != nil {
		t.Fatalf("CIBA VerifyCIBA must not collide with authorize jti: %v", err)
	}
	if _, err := v.VerifyCIBA(context.Background(), raw, testClientID, newClient()); !errors.Is(err, jar.ErrJTIReplayed) {
		t.Fatalf("err=%v want ErrJTIReplayed for second CIBA use", err)
	}
}

func TestVerify_JTIReplayTTLHasMaxAgeAndSkewFloor(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	jtis := &captureJTIStore{}
	priv, keys := jtiKey(t, testKID)
	c := happyClaims(now)
	c["nbf"] = now.Unix()
	c["jti"] = "short-exp"
	c["exp"] = now.Add(time.Second).Unix()
	raw := signClaims(t, priv, testKID, c, josev4.ES256)

	v, err := jar.NewVerifier(jar.VerifierConfig{
		Issuer:        testIssuer,
		Resolver:      &staticResolver{keys: keys},
		Clock:         fakeClock{now: now},
		MaxAge:        2 * time.Minute,
		MaxFutureSkew: 5 * time.Second,
		JTIs:          jtis,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if _, err := v.Verify(context.Background(), raw, testClientID, newClient()); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	want := now.Add(2*time.Minute + 5*time.Second)
	if !jtis.expiresAt.Equal(want) {
		t.Fatalf("jti expiresAt=%s want %s", jtis.expiresAt, want)
	}
}

// TestNewVerifier_RequiresJTIStoreOrOptOut asserts the construction-
// time guard: a JAR verifier built without a JTIs store and without
// AllowMissingJTI fails fast at startup.
func TestNewVerifier_RequiresJTIStoreOrOptOut(t *testing.T) {
	t.Parallel()
	_, err := jar.NewVerifier(jar.VerifierConfig{
		Issuer:   testIssuer,
		Resolver: &staticResolver{},
	})
	if err == nil {
		t.Fatal("expected NewVerifier to reject missing JTIs store")
	}
}

type captureJTIStore struct {
	key       string
	expiresAt time.Time
}

func (s *captureJTIStore) Mark(_ context.Context, key string, expiresAt time.Time) error {
	if s.key == key {
		return store.ErrAlreadyConsumed
	}
	s.key = key
	s.expiresAt = expiresAt
	return nil
}

func (s *captureJTIStore) Has(_ context.Context, key string) (bool, error) {
	return s.key == key, nil
}
