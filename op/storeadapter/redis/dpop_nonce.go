package oidcredis

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

// dpopNonceKeySuffix follows the key prefix in the name of the hash that
// holds the shared nonce state.
const dpopNonceKeySuffix = "dpop_nonce"

// dpopNonceBytes is the entropy of one nonce, the size the in-memory
// source mints.
const dpopNonceBytes = 16

// dpopNonceOpTimeout bounds one Redis round trip. IssueNonce and Validate
// carry no context, and the verifier calls them on the request path.
const dpopNonceOpTimeout = 2 * time.Second

// syncDPoPNonceLua advances the shared nonce state and returns it.
//
// The hash holds "cur", "prev" and "at" (the instant "cur" was installed,
// in Unix microseconds). A state older than one rotation interval installs
// the candidate and demotes "cur" to "prev"; one older than two drops
// "prev" instead, because the value it would demote has already been
// outside the accepted window. The script is one atomic operation, so
// replicas that race over a rotation agree on a single new value.
//
// KEYS[1] is the state hash. ARGV[1] is a candidate nonce, ARGV[2] the
// adapter's current instant in Unix microseconds, ARGV[3] the rotation
// interval in microseconds and ARGV[4] the key's time-to-live in
// milliseconds. It returns {cur, prev}.
const syncDPoPNonceLua = `
local state = redis.call("HMGET", KEYS[1], "cur", "prev", "at")
local cur, prev, at = state[1], state[2], tonumber(state[3])
local now, rotate = tonumber(ARGV[2]), tonumber(ARGV[3])
if not cur or not at then
	cur, prev = ARGV[1], ""
elseif now - at >= 2 * rotate then
	cur, prev = ARGV[1], ""
elseif now - at >= rotate then
	cur, prev = ARGV[1], cur
else
	return {cur, prev or ""}
end
redis.call("HSET", KEYS[1], "cur", cur, "prev", prev, "at", ARGV[2])
redis.call("PEXPIRE", KEYS[1], ARGV[4])
return {cur, prev}
`

// DPoPNonceOption configures a [DPoPNonceSource].
type DPoPNonceOption func(*DPoPNonceSource)

// WithDPoPNonceLogger sends a WARN line to logger each time the shared state
// cannot be read or advanced. A nil logger disables the line; the failures
// are counted either way, see [DPoPNonceSource.Failures].
func WithDPoPNonceLogger(logger *slog.Logger) DPoPNonceOption {
	return func(s *DPoPNonceSource) { s.logger = logger }
}

// DPoPNonceSource is an op.DPoPNonceSource that shares its nonces through
// Redis, so every replica of an OP issues and accepts the same values.
// Obtain one from [Store.DPoPNonceSource].
//
// It rotates one 128-bit random value every rotation interval and accepts
// the current and the immediately preceding value, as
// op.NewInMemoryDPoPNonceSource does. Rotation needs no goroutine: the first
// call after the interval has elapsed, on any replica, installs the new
// value. Intervals are measured on the [Store]'s clock, so replicas should
// run clocks that agree to well under the rotation interval.
//
// When Redis cannot be reached IssueNonce returns the empty string, which
// the verifier reports as a challenge without a DPoP-Nonce header, and
// Validate returns false, so a Redis outage rejects nonce-bearing proofs
// rather than accepting them. If the state key is evicted, the next call
// mints a fresh value and clients holding the old one retry once. Keep the
// key on an instance whose eviction policy spares it, or accept that retry.
// Methods are safe for concurrent use.
type DPoPNonceSource struct {
	store  *Store
	rotate time.Duration
	script *redis.Script
	rand   io.Reader
	logger *slog.Logger

	failures atomic.Uint64
}

// DPoPNonceSource returns a nonce source backed by this store that rotates
// every rotate. rotate MUST be strictly positive and at least one
// millisecond; the cadence is a security-relevant policy the adapter will
// not choose for you. The state lives in a single key under the store's key
// prefix, so replicas that should share nonces must share the prefix.
//
// Pass the result to op.WithDPoPNonceSource:
//
//	src, err := store.DPoPNonceSource(time.Minute)
//	if err != nil {
//		return err
//	}
//	provider, err := op.New( /* ... */ , op.WithDPoPNonceSource(src))
func (s *Store) DPoPNonceSource(rotate time.Duration, opts ...DPoPNonceOption) (*DPoPNonceSource, error) {
	if rotate < time.Millisecond {
		return nil, errors.New("oidcredis: DPoPNonceSource requires a rotation interval of at least one millisecond")
	}
	src := &DPoPNonceSource{
		store:  s,
		rotate: rotate,
		script: redis.NewScript(syncDPoPNonceLua),
		rand:   rand.Reader,
	}
	for _, o := range opts {
		if o != nil {
			o(src)
		}
	}
	return src, nil
}

// IssueNonce implements op.DPoPNonceSource. It returns the current value, or
// the empty string when the shared state is unavailable.
func (s *DPoPNonceSource) IssueNonce() string {
	cur, _, err := s.sync()
	if err != nil {
		return ""
	}
	return cur
}

// Validate implements op.DPoPNonceSource. It accepts the current and the
// immediately preceding value, comparing both in constant time without an
// early return. The empty string and an unavailable state are rejected.
func (s *DPoPNonceSource) Validate(nonce string) bool {
	if nonce == "" {
		return false
	}
	cur, prev, err := s.sync()
	if err != nil {
		return false
	}
	matchCurrent := subtle.ConstantTimeCompare([]byte(nonce), []byte(cur))
	matchPrevious := subtle.ConstantTimeCompare([]byte(nonce), []byte(prev))
	return (matchCurrent | matchPrevious) == 1
}

// Failures reports how many calls could not read or advance the shared
// state. The counter is monotonic; a non-zero, growing value means Redis is
// unreachable or the entropy source failed.
func (s *DPoPNonceSource) Failures() uint64 { return s.failures.Load() }

// sync advances the shared state to the store's clock and returns the
// current and previous values.
func (s *DPoPNonceSource) sync() (cur, prev string, err error) {
	cur, prev, err = s.run()
	if err != nil {
		s.failures.Add(1)
		if s.logger != nil {
			s.logger.Warn("oidcredis: DPoP nonce state unavailable", slog.Uint64("failures", s.failures.Load()))
		}
	}
	return cur, prev, err
}

func (s *DPoPNonceSource) run() (cur, prev string, err error) {
	var raw [dpopNonceBytes]byte
	if _, err := io.ReadFull(s.rand, raw[:]); err != nil {
		return "", "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), dpopNonceOpTimeout)
	defer cancel()
	res, err := s.script.Run(ctx, s.store.client,
		[]string{s.store.prefix + dpopNonceKeySuffix},
		base64.RawURLEncoding.EncodeToString(raw[:]),
		strconv.FormatInt(s.store.clock.Now().UnixMicro(), 10),
		strconv.FormatInt(s.rotate.Microseconds(), 10),
		ceilMillis(3*s.rotate),
	).StringSlice()
	if err != nil {
		return "", "", err
	}
	if len(res) != 2 || res[0] == "" {
		return "", "", errors.New("oidcredis: unexpected DPoP nonce script reply")
	}
	return res[0], res[1], nil
}
