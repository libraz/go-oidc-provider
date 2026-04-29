package op

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
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
// in-memory KV with replication); a built-in distributed implementation
// is on the v1.x roadmap.
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
func NewInMemoryDPoPNonceSource(ctx context.Context, rotate time.Duration, opts ...InMemoryDPoPNonceOption) (*InMemoryDPoPNonceSource, error) {
	if rotate <= 0 {
		return nil, errors.New("op: NewInMemoryDPoPNonceSource requires a positive rotation interval")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	src := &InMemoryDPoPNonceSource{rand: rand.Reader}
	for _, o := range opts {
		if o != nil {
			o(src)
		}
	}
	first, err := src.randomNonceValue()
	if err != nil {
		return nil, err
	}
	src.current = first
	go src.run(ctx, rotate)
	return src, nil
}

// InMemoryDPoPNonceOption configures the optional behaviour of an
// [InMemoryDPoPNonceSource]. Options are functional so the constructor
// signature stays stable as new knobs are added; embedders typically
// pass [WithInMemoryDPoPNonceLogger] so a misbehaving entropy source
// surfaces in their operational stream.
type InMemoryDPoPNonceOption func(*InMemoryDPoPNonceSource)

// WithInMemoryDPoPNonceLogger wires the supplied [*slog.Logger] to the
// nonce source so a [crypto/rand.Reader] failure during the rotation
// goroutine emits a WARN line tagged with the rotation-failure counter.
// The library deliberately does NOT introduce a separate top-level
// option for this seam — the embedder's existing root logger configured
// through [WithLogger] is the right home for the diagnostic, and the
// caller threads it in here when constructing the helper directly.
//
// A nil logger is treated as "no logging" so the option is safe to call
// unconditionally with whatever the embedder happens to have on hand.
func WithInMemoryDPoPNonceLogger(logger *slog.Logger) InMemoryDPoPNonceOption {
	return func(s *InMemoryDPoPNonceSource) {
		s.logger = logger
	}
}

// withInMemoryDPoPNonceRand overrides the entropy source used when
// generating fresh nonce values. The seam exists exclusively for tests
// that pin a faulty [io.Reader] to exercise the rotation-failure path;
// it is unexported to keep the production API minimal.
func withInMemoryDPoPNonceRand(r io.Reader) InMemoryDPoPNonceOption {
	return func(s *InMemoryDPoPNonceSource) {
		if r != nil {
			s.rand = r
		}
	}
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

	// rand is the entropy source used to mint fresh nonce values. It
	// defaults to [crypto/rand.Reader]; tests override the field via
	// the unexported withInMemoryDPoPNonceRand option to exercise the
	// rotation-failure path without globally swapping rand.Reader.
	rand io.Reader

	// logger receives WARN lines when the rotation goroutine cannot
	// mint a fresh value. Nil means "no logging"; the field is
	// populated by [WithInMemoryDPoPNonceLogger] so embedders can
	// thread their root logger through without a separate top-level
	// option.
	logger *slog.Logger

	// rotationFailures counts the rotation ticks that could not mint
	// a fresh nonce because [io.Reader.Read] returned an error. The
	// counter is exported through [InMemoryDPoPNonceSource.RotationFailures]
	// so embedders can wire it into their own metrics surface; the
	// library does not expose it via [WithPrometheus] because the
	// helper's lifecycle is owned by the embedder.
	rotationFailures atomic.Uint64
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
//
// The comparison against current and previous uses
// [crypto/subtle.ConstantTimeCompare] and combines the two results
// without an early return. A timing attack that tried to learn the
// matched slot ("did the value collide with current or previous?")
// gains no signal from this implementation: both compares run on
// every call, and the function returns the OR of their results
// without short-circuiting. Length-mismatched inputs are forced to
// length-equal scratch buffers so [subtle.ConstantTimeCompare] does
// not bail out early.
func (s *InMemoryDPoPNonceSource) Validate(nonce string) bool {
	if nonce == "" {
		return false
	}
	s.mu.RLock()
	current := s.current
	previous := s.previous
	s.mu.RUnlock()

	matchCurrent := constantTimeStringEqual(nonce, current)
	matchPrevious := constantTimeStringEqual(nonce, previous)
	// Combine without early return so the branch the matched value
	// took is not observable through timing.
	return (matchCurrent | matchPrevious) == 1
}

// RotationFailures reports the number of rotation ticks that could
// not mint a fresh nonce because the configured entropy source
// returned an error. The counter is monotonic and safe for
// concurrent reads. Embedders typically scrape it from their metrics
// pipeline alongside the operational logger configured through
// [WithInMemoryDPoPNonceLogger]; a non-zero value indicates the
// rotation goroutine is degraded and the helper has been serving the
// previous nonce for longer than the configured rotation cadence.
func (s *InMemoryDPoPNonceSource) RotationFailures() uint64 {
	return s.rotationFailures.Load()
}

// constantTimeStringEqual reports whether a and b are the same byte
// sequence in constant time relative to the input length. The helper
// pads the shorter side onto a scratch buffer of len(a) so
// [crypto/subtle.ConstantTimeCompare] sees length-equal inputs and
// does not return early on a mismatch. The result is 1 when equal,
// 0 otherwise.
func constantTimeStringEqual(a, b string) int {
	if len(a) != len(b) {
		// Force the compare to run against a length-equal scratch
		// buffer so the early-return inside ConstantTimeCompare does
		// not leak the length difference. The OR with the length
		// inequality forces a 0 result regardless of the digest match.
		scratch := make([]byte, len(a))
		_ = subtle.ConstantTimeCompare([]byte(a), scratch)
		return 0
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b))
}

// run drives the rotation ticker until ctx is canceled. A failure
// inside [InMemoryDPoPNonceSource.randomNonceValue] degrades
// gracefully: the source keeps the previous value as current so the
// next IssueNonce call still returns a non-empty string. Returning
// empty would surface as a missing DPoP-Nonce header on the wire,
// which the verifier already documents as "issuer offline". The
// failure is surfaced through three independent channels so a silent
// entropy outage cannot go unnoticed:
//
//   - [InMemoryDPoPNonceSource.RotationFailures] increments by one,
//   - the configured logger (when [WithInMemoryDPoPNonceLogger] was
//     supplied) emits a WARN line tagged with the running counter,
//   - the rotation goroutine continues to tick so a subsequent
//     successful read still rotates the value.
func (s *InMemoryDPoPNonceSource) run(ctx context.Context, rotate time.Duration) {
	t := time.NewTicker(rotate)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			fresh, err := s.randomNonceValue()
			if err != nil {
				// Emit the log BEFORE bumping the counter so a test
				// (or operator scrape) that wakes on RotationFailures()
				// always finds the matching log line already flushed
				// to the configured handler. Reversing the order
				// introduces a race between the counter observer and
				// the log writer.
				count := s.rotationFailures.Load() + 1
				if s.logger != nil {
					s.logger.Warn(
						"op: InMemoryDPoPNonceSource rotation failed; serving the previous nonce",
						"error", err,
						"rotation_failures", count,
					)
				}
				s.rotationFailures.Store(count)
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
// realistic rotation cadence. The helper reads from
// [InMemoryDPoPNonceSource.rand] (defaulting to [crypto/rand.Reader])
// so tests can pin a faulty source without globally swapping the
// package-level reader.
func (s *InMemoryDPoPNonceSource) randomNonceValue() (string, error) {
	buf := make([]byte, 16)
	reader := s.rand
	if reader == nil {
		reader = rand.Reader
	}
	if _, err := io.ReadFull(reader, buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
