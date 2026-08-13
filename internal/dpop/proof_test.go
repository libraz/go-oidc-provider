package dpop_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/url"
	"sync"
	"testing"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/libraz/go-oidc-provider/internal/dpop"
	"github.com/libraz/go-oidc-provider/op/store"
)

// signKey is a deterministic test key bundle: an [ecdsa.PrivateKey] or
// [ed25519.PrivateKey] paired with a tiny constructor so callers can
// build proofs without re-hashing the boilerplate per test.
type signKey struct {
	priv crypto.Signer
	alg  josev4.SignatureAlgorithm
}

func newES256Key(t testing.TB) signKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	return signKey{priv: priv, alg: josev4.ES256}
}

func newEdKey(t testing.TB) signKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return signKey{priv: priv, alg: josev4.EdDSA}
}

func newPS256Key(t testing.TB) signKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return signKey{priv: priv, alg: josev4.PS256}
}

// signProof returns a compact-serialised DPoP proof carrying claims and
// the appropriate "typ" / "jwk" headers. typ defaults to "dpop+jwt"
// when override is empty.
func signProof(t testing.TB, key signKey, claims map[string]any, typOverride string) string {
	t.Helper()
	pub := key.priv.Public()
	jwk := josev4.JSONWebKey{Key: pub}
	typ := "dpop+jwt"
	if typOverride != "" {
		typ = typOverride
	}
	signer, err := josev4.NewSigner(
		josev4.SigningKey{Algorithm: key.alg, Key: key.priv},
		(&josev4.SignerOptions{}).
			WithType(josev4.ContentType(typ)).
			WithHeader("jwk", jwk),
	)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	tok, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	return tok
}

// goodClaims returns a claim map every "happy path" test starts from.
// The "iat" anchor matches the test fixtures' deterministic clock.
func goodClaims(now time.Time) map[string]any {
	return map[string]any{
		"jti": "jti-1",
		"htm": "POST",
		"htu": "https://op.example/oidc/token",
		"iat": now.Unix(),
	}
}

// memJTIStore is the local in-memory [store.ConsumedJTIStore] used by
// every Verify-driven test. It mirrors the production behaviour
// closely enough that the dpop package's contract is exercised end-to-
// end.
type memJTIStore struct {
	mu sync.Mutex
	m  map[string]time.Time
}

func newMemJTIStore() *memJTIStore { return &memJTIStore{m: map[string]time.Time{}} }

func (s *memJTIStore) Mark(_ context.Context, jti string, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, dup := s.m[jti]; dup {
		return store.ErrAlreadyConsumed
	}
	s.m[jti] = expiresAt
	return nil
}

func (s *memJTIStore) Has(_ context.Context, jti string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.m[jti]
	return ok, nil
}

// len reports how many replay entries the store holds. Tests that
// assert a refused proof left the table untouched read it.
func (s *memJTIStore) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.m)
}

// expiryOf returns the retention deadline recorded for jti, or the zero
// time when the entry is absent.
func (s *memJTIStore) expiryOf(jti string) time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[jti]
}

type captureJTIStore struct {
	jti       string
	expiresAt time.Time
}

func (s *captureJTIStore) Mark(_ context.Context, jti string, expiresAt time.Time) error {
	if s.jti == jti {
		return store.ErrAlreadyConsumed
	}
	s.jti = jti
	s.expiresAt = expiresAt
	return nil
}

func (s *captureJTIStore) Has(_ context.Context, jti string) (bool, error) {
	return s.jti == jti, nil
}

// fixedClock is the test-side wall clock pinned to a single Now() value.
type fixedClock struct{ now time.Time }

func (f fixedClock) Now() time.Time { return f.now }

// newVerifier wires a fresh in-memory replay store + clock + Verifier
// for the supplied "now" anchor.
func newVerifier(t testing.TB, now time.Time) *dpop.Verifier {
	t.Helper()
	v, err := dpop.NewVerifier(dpop.VerifierConfig{
		JTIs:  newMemJTIStore(),
		Clock: fixedClock{now: now},
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}

func mustParseURL(t testing.TB, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", raw, err)
	}
	return u
}

func TestVerify_HappyES256(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	key := newES256Key(t)
	raw := signProof(t, key, goodClaims(now), "")
	v := newVerifier(t, now)
	out, err := v.Verify(context.Background(), dpop.VerifyInput{
		ProofHeader: raw,
		Method:      "POST",
		URL:         mustParseURL(t, "https://op.example/oidc/token"),
		TLS:         true,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if out.JKT == "" {
		t.Fatal("JKT must be populated")
	}
	if out.JTI != "jti-1" {
		t.Errorf("JTI=%q want jti-1", out.JTI)
	}
}

func TestVerify_HappyEd25519(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	key := newEdKey(t)
	raw := signProof(t, key, goodClaims(now), "")
	v := newVerifier(t, now)
	if _, err := v.Verify(context.Background(), dpop.VerifyInput{
		ProofHeader: raw,
		Method:      "POST",
		URL:         mustParseURL(t, "https://op.example/oidc/token"),
		TLS:         true,
	}); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerify_HappyPS256(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	key := newPS256Key(t)
	raw := signProof(t, key, goodClaims(now), "")
	v := newVerifier(t, now)
	out, err := v.Verify(context.Background(), dpop.VerifyInput{
		ProofHeader: raw,
		Method:      "POST",
		URL:         mustParseURL(t, "https://op.example/oidc/token"),
		TLS:         true,
	})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if out.JKT == "" {
		t.Fatal("JKT must be populated")
	}
}

func TestVerify_RejectsEmpty(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	v := newVerifier(t, now)
	_, err := v.Verify(context.Background(), dpop.VerifyInput{
		ProofHeader: "",
		Method:      "POST",
		URL:         mustParseURL(t, "https://op.example/oidc/token"),
		TLS:         true,
	})
	if !errors.Is(err, dpop.ErrProofMalformed) {
		t.Fatalf("err=%v want ErrProofMalformed", err)
	}
}

func TestVerify_RejectsWrongTyp(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	key := newES256Key(t)
	raw := signProof(t, key, goodClaims(now), "JWT")
	v := newVerifier(t, now)
	_, err := v.Verify(context.Background(), dpop.VerifyInput{
		ProofHeader: raw,
		Method:      "POST",
		URL:         mustParseURL(t, "https://op.example/oidc/token"),
		TLS:         true,
	})
	if !errors.Is(err, dpop.ErrProofMalformed) {
		t.Fatalf("err=%v want ErrProofMalformed", err)
	}
}

func TestVerify_RejectsHS256(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	const sym = "0123456789abcdef0123456789abcdef"
	signer, err := josev4.NewSigner(
		josev4.SigningKey{Algorithm: josev4.HS256, Key: []byte(sym)},
		(&josev4.SignerOptions{}).WithType("dpop+jwt"),
	)
	if err != nil {
		t.Skipf("HS256 signer construction rejected: %v", err)
	}
	raw, err := jwt.Signed(signer).Claims(goodClaims(now)).Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	v := newVerifier(t, now)
	_, perr := v.Verify(context.Background(), dpop.VerifyInput{
		ProofHeader: raw,
		Method:      "POST",
		URL:         mustParseURL(t, "https://op.example/oidc/token"),
		TLS:         true,
	})
	if !errors.Is(perr, dpop.ErrProofMalformed) {
		t.Fatalf("err=%v want ErrProofMalformed", perr)
	}
}

func TestVerify_MissingJWK(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	key := newES256Key(t)
	signer, err := josev4.NewSigner(
		josev4.SigningKey{Algorithm: key.alg, Key: key.priv},
		(&josev4.SignerOptions{}).WithType("dpop+jwt"),
	)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	raw, err := jwt.Signed(signer).Claims(goodClaims(now)).Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	v := newVerifier(t, now)
	_, perr := v.Verify(context.Background(), dpop.VerifyInput{
		ProofHeader: raw,
		Method:      "POST",
		URL:         mustParseURL(t, "https://op.example/oidc/token"),
		TLS:         true,
	})
	if !errors.Is(perr, dpop.ErrProofMalformed) {
		t.Fatalf("err=%v want ErrProofMalformed", perr)
	}
}

// TestVerify_RejectsPrivateKeyInJWKHeader pins RFC 9449 §4.3 step 7: a
// DPoP proof whose embedded "jwk" header carries private key material
// (the EC "d" component) MUST be rejected. The "jwk" header is reserved
// for the client's public key; a private component signals a malformed /
// hostile proof, and accepting it leaks key material through a header the
// spec forbids from carrying it.
//
// Tracks: CVE-2026-54431 (liboauth2) — the DPoP verifier returned
// success for a proof whose jwk header embedded the private EC key,
// violating RFC 9449 §4.3 step 7. The structural property is that the
// embedded jwk must be public-only; any private parameter is a hard
// reject before the claim bag is trusted.
func TestVerify_RejectsPrivateKeyInJWKHeader(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	key := newES256Key(t)
	// Embed the FULL private key in the jwk header (Key: key.priv, not
	// its Public()); the serialised JWK then carries the private "d"
	// component — the exact malformed proof RFC 9449 §4.3 step 7 rejects.
	privJWK := josev4.JSONWebKey{Key: key.priv}
	signer, err := josev4.NewSigner(
		josev4.SigningKey{Algorithm: key.alg, Key: key.priv},
		(&josev4.SignerOptions{}).
			WithType("dpop+jwt").
			WithHeader("jwk", privJWK),
	)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	raw, err := jwt.Signed(signer).Claims(goodClaims(now)).Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	v := newVerifier(t, now)
	_, perr := v.Verify(context.Background(), dpop.VerifyInput{
		ProofHeader: raw,
		Method:      "POST",
		URL:         mustParseURL(t, "https://op.example/oidc/token"),
		TLS:         true,
	})
	if !errors.Is(perr, dpop.ErrProofMalformed) {
		t.Fatalf("err=%v want ErrProofMalformed (private key in jwk header)", perr)
	}
}

func TestVerify_BadSignature(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	key := newES256Key(t)
	raw := signProof(t, key, goodClaims(now), "")
	tampered := raw[:len(raw)-4] + "AAAA"
	v := newVerifier(t, now)
	_, err := v.Verify(context.Background(), dpop.VerifyInput{
		ProofHeader: tampered,
		Method:      "POST",
		URL:         mustParseURL(t, "https://op.example/oidc/token"),
		TLS:         true,
	})
	if !errors.Is(err, dpop.ErrProofSignature) {
		t.Fatalf("err=%v want ErrProofSignature", err)
	}
}

func TestVerify_MissingJTI(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	key := newES256Key(t)
	claims := goodClaims(now)
	delete(claims, "jti")
	raw := signProof(t, key, claims, "")
	v := newVerifier(t, now)
	_, err := v.Verify(context.Background(), dpop.VerifyInput{
		ProofHeader: raw,
		Method:      "POST",
		URL:         mustParseURL(t, "https://op.example/oidc/token"),
		TLS:         true,
	})
	if !errors.Is(err, dpop.ErrProofMissingJTI) {
		t.Fatalf("err=%v want ErrProofMissingJTI", err)
	}
}

func TestVerify_MissingHTU(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	key := newES256Key(t)
	claims := goodClaims(now)
	delete(claims, "htu")
	raw := signProof(t, key, claims, "")
	v := newVerifier(t, now)
	_, err := v.Verify(context.Background(), dpop.VerifyInput{
		ProofHeader: raw,
		Method:      "POST",
		URL:         mustParseURL(t, "https://op.example/oidc/token"),
		TLS:         true,
	})
	if !errors.Is(err, dpop.ErrProofMalformed) {
		t.Fatalf("err=%v want ErrProofMalformed", err)
	}
}

func TestVerify_MissingIAT(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	key := newES256Key(t)
	claims := goodClaims(now)
	delete(claims, "iat")
	raw := signProof(t, key, claims, "")
	v := newVerifier(t, now)
	_, err := v.Verify(context.Background(), dpop.VerifyInput{
		ProofHeader: raw,
		Method:      "POST",
		URL:         mustParseURL(t, "https://op.example/oidc/token"),
		TLS:         true,
	})
	if !errors.Is(err, dpop.ErrProofMalformed) {
		t.Fatalf("err=%v want ErrProofMalformed", err)
	}
}

func TestVerify_HTUStripsQueryAndCaseFolds(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	key := newES256Key(t)
	// The proof carries the canonical lowercase htu; the request URL
	// arrives upper-cased and with a query string. The verifier MUST
	// match them after normalisation (RFC 9449 §4.3).
	claims := goodClaims(now)
	claims["htu"] = "https://op.example/oidc/token"
	raw := signProof(t, key, claims, "")
	v := newVerifier(t, now)
	if _, err := v.Verify(context.Background(), dpop.VerifyInput{
		ProofHeader: raw,
		Method:      "POST",
		URL:         mustParseURL(t, "https://OP.EXAMPLE/oidc/token?cache=1#frag"),
		TLS:         true,
	}); err != nil {
		t.Fatalf("Verify must accept normalised htu: %v", err)
	}
}
