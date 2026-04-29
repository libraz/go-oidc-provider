package op

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

// NewInMemoryDPoPNonceSource returns a [DPoPNonceSource] that rotates a
// single 128-bit random value every rotate interval and accepts the
// current and immediately preceding values from clients. The helper is
// the project's reference implementation for the RFC 9449 §8 / §9
// nonce flow on single-process deployments — small to medium SaaS
// surfaces, internal tooling, embedded admin OPs, and demos.
//
// The returned source is NOT suitable for horizontally-scaled OPs: it
// has no shared backing store, so two replicas issuing nonces from
// different processes would each accept only their own ring and reject
// the other's, generating a thrash of use_dpop_nonce challenges. A
// production deployment that needs more than one replica MUST supply a
// distributed nonce source backed by a shared cache (Redis, memcached,
// in-memory KV with replication) — see the v1.x Wave L3 outlook.
//
// rotate MUST be strictly positive. A zero or negative value returns
// an error rather than silently substituting a default; the choice of
// rotation cadence is a security-relevant policy and the library will
// not pick one on the embedder's behalf. Typical values are in the
// 30-second to 5-minute range; RFC 9449 §8 leaves the cadence to the
// OP, but a window short enough to defeat replay yet long enough to
// survive a typical client retry burst is the recommended target.
//
// The supplied ctx governs the rotation goroutine. When ctx is nil
// the source uses [context.Background] and the ticker runs for the
// lifetime of the process. When ctx is canceled the ticker stops; the
// source keeps serving the nonces it had already minted so in-flight
// validations do not start failing on shutdown — issuance simply
// stops advancing. Pass a request-scoped or test-scoped context if
// you need deterministic shutdown / GC.
//
// Stable since v0.x.
func NewInMemoryDPoPNonceSource(ctx context.Context, rotate time.Duration) (*InMemoryDPoPNonceSource, error) {
	if rotate <= 0 {
		return nil, errors.New("op: NewInMemoryDPoPNonceSource requires a positive rotation interval")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	first, err := randomNonceValue()
	if err != nil {
		return nil, err
	}
	src := &InMemoryDPoPNonceSource{current: first}
	go src.run(ctx, rotate)
	return src, nil
}

// InMemoryDPoPNonceSource is the concrete reference implementation of
// [DPoPNonceSource] returned by [NewInMemoryDPoPNonceSource]. The
// struct satisfies the interface; the constructor returns the concrete
// type so callers can extend it (e.g. wrap with metrics) without
// re-implementing the rotation machinery. Methods are safe for
// concurrent use.
type InMemoryDPoPNonceSource struct {
	mu       sync.RWMutex
	current  string
	previous string
}

// IssueNonce implements [DPoPNonceSource]. It returns the current
// value; the rotation goroutine periodically replaces it.
func (s *InMemoryDPoPNonceSource) IssueNonce() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current
}

// Validate implements [DPoPNonceSource]. It accepts the current and
// the immediately preceding value so an in-flight client retry that
// straddles a rotation does not get rejected. The empty string is
// rejected directly; the verifier already short-circuits empty input
// before this method runs but the explicit check keeps the helper
// safe to embed outside the verifier.
func (s *InMemoryDPoPNonceSource) Validate(nonce string) bool {
	if nonce == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return nonce == s.current || nonce == s.previous
}

// run drives the rotation ticker until ctx is canceled. A failure
// inside [randomNonceValue] degrades gracefully: the source keeps the
// previous value as current so the next IssueNonce call still returns
// a non-empty string. Returning empty would surface as a missing
// DPoP-Nonce header on the wire, which the verifier already documents
// as "issuer offline".
func (s *InMemoryDPoPNonceSource) run(ctx context.Context, rotate time.Duration) {
	t := time.NewTicker(rotate)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			fresh, err := randomNonceValue()
			if err != nil {
				continue
			}
			s.mu.Lock()
			s.previous = s.current
			s.current = fresh
			s.mu.Unlock()
		}
	}
}

// randomNonceValue returns a 128-bit random nonce encoded as
// base64url. 128 bits matches the OAuth client-id randomness target
// (RFC 6749 §10.4) and is well above the birthday-bound for any
// realistic rotation cadence.
func randomNonceValue() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
