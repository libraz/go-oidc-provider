//go:build example

// Example 51 demonstrates the RFC 9449 §8 / §9 server-supplied DPoP
// nonce flow. The /token and /userinfo handlers reject any DPoP
// proof whose "nonce" claim is missing or stale, returning the
// "use_dpop_nonce" challenge along with a fresh value in the
// DPoP-Nonce response header. The client retries with the new nonce.
//
// Run with the example build tag:
//
//	go run -tags example ./examples/51-dpop-nonce
//
// Trigger the challenge from a no-nonce DPoP proof (the RP would
// normally produce this on the first call, observe the challenge,
// and retry):
//
//	# Build a DPoP proof JWT without a nonce claim — see
//	# https://datatracker.ietf.org/doc/html/rfc9449#section-4.2 for
//	# the unsigned shape. The OP returns a 400 / use_dpop_nonce error
//	# and stamps the next acceptable nonce into DPoP-Nonce.
//	curl -sS -i -X POST http://localhost:8080/oidc/token \
//	  -H 'DPoP: <proof-without-nonce>' \
//	  -d 'grant_type=authorization_code&code=...' | head -20
//
// Wiring details:
//
//   - WithFeature(feature.DPoP) enables the DPoP verifier on /token
//     and /userinfo. Without it the nonce source is a no-op.
//   - WithDPoPNonceSource installs the issuance / validation halves.
//     The implementation below rotates a single value every 60
//     seconds and accepts the current and previous values, which is
//     enough for a casual demo. Production sources stamp a signed
//     payload that carries an embedded expiry so they survive a
//     process restart.
//
// PRODUCTION CAVEATS: this example uses ephemeral keys, a
// process-local nonce ring (forgets all values on restart), and a
// public HTTP listener. Production embedders place the nonce source
// behind a shared cache (Redis / memcached) so a horizontally
// scaled OP fleet stays consistent.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// rotatingNonceSource is the embedder-supplied DPoPNonceSource.
// IssueNonce returns the current value; Validate accepts the current
// or the immediately previous value so an in-flight client retry that
// straddles a rotation does not get rejected.
type rotatingNonceSource struct {
	mu       sync.RWMutex
	current  string
	previous string
}

func newRotatingNonceSource(rotateEvery time.Duration) *rotatingNonceSource {
	src := &rotatingNonceSource{current: randomNonce()}
	go func() {
		t := time.NewTicker(rotateEvery)
		defer t.Stop()
		for range t.C {
			src.rotate()
		}
	}()
	return src
}

func (s *rotatingNonceSource) IssueNonce() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current
}

func (s *rotatingNonceSource) Validate(nonce string) bool {
	if nonce == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return nonce == s.current || nonce == s.previous
}

func (s *rotatingNonceSource) rotate() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.previous = s.current
	s.current = randomNonce()
}

func randomNonce() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		log.Fatalf("rand.Read: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

func main() {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("generate signing key: %v", err)
	}
	cookieKey := make([]byte, 32)
	if _, err := rand.Read(cookieKey); err != nil {
		log.Fatalf("generate cookie key: %v", err)
	}

	provider, err := op.New(
		op.WithIssuer("https://op.example.com"),
		op.WithStore(inmem.New()),
		op.WithKeyset(op.Keyset{{KeyID: "dpop-nonce-1", Signer: priv}}),
		op.WithCookieKey(cookieKey),
		op.WithFeature(feature.DPoP),
		op.WithDPoPNonceSource(newRotatingNonceSource(60*time.Second)),
		op.WithStaticClients(
			op.PublicClient{
				ID:           "demo-spa",
				RedirectURIs: []string{"http://localhost:5173/callback"},
				Scopes:       []string{"openid", "profile"},
			},
		),
	)
	if err != nil {
		log.Fatalf("op.New: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", provider)

	log.Println("dpop-nonce example listening on :8080")
	log.Println("DPoP feature enabled; nonces rotate every 60s")
	log.Println("a DPoP proof without a 'nonce' claim now triggers RFC 9449 use_dpop_nonce")
	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
