package oidcredis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/libraz/go-oidc-provider/op/store"
	"github.com/libraz/go-oidc-provider/op/storeadapter/patterns"
)

// jtiStore implements [store.ConsumedJTIStore] against Redis.
//
// # Why the marker carries its own expiry
//
// Redis key expiry is governed by the Redis server's clock, which the
// OP cannot read and an embedder cannot inject. The marker therefore
// stores its expiresAt in the value, and both Mark and Has re-evaluate
// it against the adapter clock instead of trusting key presence. The
// same shape the interaction and session substores use.
//
// This closes exactly one of the two skew directions, and it is worth
// being precise about which:
//
//   - A server that is slow to reclaim — its clock lags, or it simply
//     has not got round to the key — keeps a marker resident past its
//     expiresAt. Without the stored expiry, EXISTS reports it live and
//     a legitimate fresh request carrying that jti is refused as a
//     replay. Re-checking against the adapter clock fixes this.
//   - A server that reclaims early — its clock runs ahead, or the key
//     was evicted under memory pressure — removes a marker the OP still
//     considers live. Nothing is left to re-check, so Has reports the
//     jti free and a genuine replay is accepted. The stored expiry does
//     not help here and is not claimed to: guarding that direction
//     needs a durable substore, which is the routing decision declared
//     on [store.ConsumedJTIStore].
type jtiStore struct {
	parent     *Store
	markScript *redis.Script
}

// markJTILua records a replay marker unless a live one already holds
// the key. It returns 1 when the marker was recorded and 0 when the
// caller is replaying.
//
// The whole script is one atomic Redis operation, so it enforces
// first-writer-wins exactly as the SETNX it replaces did: two racing
// Marks on a free key serialise, the first records, and the second
// observes the value the first just wrote. A plain SETNX cannot be used
// on its own any more because taking over a stale marker is a decision
// about the stored value, and reading that value in the adapter before
// writing would open the race SETNX exists to prevent.
//
// KEYS[1] is the marker key. ARGV[1] is the encoded value to store,
// ARGV[2] the adapter's current instant in Unix microseconds, and
// ARGV[3] the time-to-live in milliseconds, or 0 for a marker that
// never expires.
const markJTILua = `
local current = redis.call("GET", KEYS[1])
if current then
	local expiry = string.match(current, "^e(%-?%d+)$")
	if not expiry or tonumber(expiry) > tonumber(ARGV[2]) then
		return 0
	end
end
if tonumber(ARGV[3]) > 0 then
	redis.call("SET", KEYS[1], ARGV[1], "PX", ARGV[3])
else
	redis.call("SET", KEYS[1], ARGV[1])
end
return 1
`

func newJTIStore(parent *Store) *jtiStore {
	return &jtiStore{parent: parent, markScript: redis.NewScript(markJTILua)}
}

// The marker value is either persistentJTIValue or expiringJTIPrefix
// followed by the expiresAt in decimal Unix microseconds.
//
// Microseconds rather than nanoseconds because the comparison happens
// in Lua, whose numbers are IEEE doubles: nanosecond epochs are past
// the 2^53 exact-integer range and would compare imprecisely, while
// microsecond epochs stay exact into the twenty-third century.
//
// A value in neither form was not written by this adapter, and both
// Mark and Has treat it as a live marker. That is the fail-secure
// reading: refusing a request as a replay is recoverable, accepting a
// replay is not.
const (
	persistentJTIValue = "p"
	expiringJTIPrefix  = "e"
)

// jtiKey hashes the supplied jti so the key length is bounded. JTI
// values come from JWT claims and may legitimately be long
// (RFC 7519 sets no upper bound); hashing guarantees a fixed 64-char
// hex suffix and does not leak the jti payload to anyone with redis
// SCAN access. The hash is not a secret — its only purpose is bounded
// length and deterministic key derivation.
func (j *jtiStore) jtiKey(jti string) string {
	h := sha256.Sum256([]byte(jti))
	return j.parent.prefix + "jti:" + hex.EncodeToString(h[:])
}

// Mark records jti as consumed. It returns [store.ErrAlreadyConsumed]
// when a live marker for the same jti is already present, even when its
// expiresAt has not yet been reached. A marker whose expiresAt has
// passed is stale: Mark takes the key over, which is what keeps Mark
// and [jtiStore.Has] from disagreeing at the boundary instant.
//
// A non-zero expiresAt drives the key's TTL; an expiresAt already in
// the past returns nil without writing (per the contract,
// already-expired records may be treated as absent on subsequent
// reads).
//
// A zero expiresAt means "no expiry" — the project-wide convention the
// inmem and SQL adapters honour by retaining the marker permanently.
// Redis expresses that as a key with no TTL; dropping such a marker
// would silently disable replay protection for any caller that passes a
// zero expiry (a third-party grant handler or an embedder marking a JTI
// directly). The past-dated short-circuit therefore applies only to a
// genuinely non-zero, elapsed expiresAt.
func (j *jtiStore) Mark(ctx context.Context, jti string, expiresAt time.Time) error {
	now := j.parent.clock.Now()
	value := persistentJTIValue
	var ttlMillis int64
	if !expiresAt.IsZero() {
		ttl := jtiTTL(now, expiresAt)
		if ttl <= 0 {
			// Past-dated marker: nothing to record, since any subsequent
			// Has call would treat the entry as absent anyway.
			return nil
		}
		value = expiringJTIPrefix + strconv.FormatInt(expiresAt.UnixMicro(), 10)
		ttlMillis = max(ttl.Milliseconds(), 1)
	}
	recorded, err := j.markScript.Run(
		ctx,
		j.parent.client,
		[]string{j.jtiKey(jti)},
		value,
		now.UnixMicro(),
		ttlMillis,
	).Int()
	if err != nil {
		return fmt.Errorf("oidcredis: mark jti: %w", err)
	}
	if recorded == 0 {
		return store.ErrAlreadyConsumed
	}
	return nil
}

func jtiTTL(now, expiresAt time.Time) time.Duration {
	return expiresAt.Sub(now)
}

// Has reports whether a live marker for jti is present. It applies the
// inclusive bound [store.ConsumedJTIStore] declares — a marker is
// expired from its expiresAt onwards — against the adapter clock, so it
// cannot disagree with [jtiStore.Mark] about the boundary instant. A key
// the Redis server has already reclaimed reads as absent either way.
func (j *jtiStore) Has(ctx context.Context, jti string) (bool, error) {
	raw, err := j.parent.client.Get(ctx, j.jtiKey(jti)).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return false, nil
		}
		return false, fmt.Errorf("oidcredis: GET jti: %w", err)
	}
	return !patterns.IsExpiredInclusive(decodeJTIExpiry(raw), j.parent.clock.Now()), nil
}

// decodeJTIExpiry reads the expiry a marker value carries. It reports
// the zero time — "no expiry", which [patterns.IsExpiredInclusive]
// treats as permanently live — both for a marker written as persistent
// and for any value this adapter did not write.
func decodeJTIExpiry(raw string) time.Time {
	micros, ok := strings.CutPrefix(raw, expiringJTIPrefix)
	if !ok {
		return time.Time{}
	}
	parsed, err := strconv.ParseInt(micros, 10, 64)
	if err != nil {
		return time.Time{}
	}
	return time.UnixMicro(parsed).UTC()
}

var _ store.ConsumedJTIStore = (*jtiStore)(nil)
