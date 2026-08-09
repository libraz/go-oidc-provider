package jwks

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/libraz/go-oidc-provider/internal/keys"
)

// CacheControl is the value the handler stamps on every successful
// response when no key rotation is currently in progress. It targets a
// 1-hour cache with a 1-hour stale-while-revalidate window, keeping
// normal traffic cacheable without delaying key rollouts for a full day.
const CacheControl = "public, max-age=3600, stale-while-revalidate=3600"

// CacheControlRotating is the value the handler stamps on responses
// while a key rotation overlap window is active. It shortens the cache
// to 5 minutes and forces revalidation so RPs whose old cached JWKS
// still names a retiring kid pick up the fresh key promptly.
const CacheControlRotating = "public, max-age=300, must-revalidate"

// HandlerOptions tunes the JWKS handler. The zero value emits the
// long-cache defaults; fields are opt-in.
type HandlerOptions struct {
	// RotationActive, when non-nil, is consulted on every request to
	// decide whether the response should advertise the shortened
	// rotation Cache-Control. The predicate runs on the request hot
	// path, so implementations MUST be cheap and concurrency-safe.
	// A nil predicate (the zero-value default) is treated as "rotation
	// inactive" — the long-cache header is emitted.
	RotationActive func() bool

	// EncryptionSet, when non-nil, contributes the OP's use=enc public
	// keys to the published JWKS. The keys appear after every signing
	// key (use=sig) so RPs that scan in order encounter signing keys
	// first. RFC 7517 §4.2 requires the same kid not to appear with
	// both use=sig and use=enc; the op layer enforces the constraint
	// at construction time so this handler can concatenate freely.
	EncryptionSet *keys.EncryptionSet
}

// Handler returns an [http.Handler] that serves the public JWKS for set.
// The returned handler is safe for concurrent use; callers MUST NOT mutate
// set after registration — the handler memoises the rendered body and a
// mutated set would be served stale (see [bodyCache]).
//
// The handler emits an ETag computed as the lowercase hex SHA-256 of
// the marshalled JSON body, wrapped in double quotes per RFC 9110
// §8.8.3 (strong validator). Callers presenting a matching value in
// [If-None-Match] receive a 304 Not Modified with no body.
//
// This is the long-form constructor; tests and callers that do not
// care about rotation state may keep using [Handler] which is just
// [HandlerWithOptions] with the zero options value.
func Handler(set *keys.Set) http.Handler {
	return HandlerWithOptions(set, HandlerOptions{})
}

// HandlerWithOptions is [Handler] with a configurable [HandlerOptions].
func HandlerWithOptions(set *keys.Set, opts HandlerOptions) http.Handler {
	cache := &bodyCache{set: set, enc: opts.EncryptionSet}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, etag, err := cache.render()
		if err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		cacheControl := CacheControl
		if opts.RotationActive != nil && opts.RotationActive() {
			cacheControl = CacheControlRotating
		}

		w.Header().Set("Content-Type", "application/jwk-set+json")
		w.Header().Set("Cache-Control", cacheControl)
		w.Header().Set("ETag", etag)

		if matchesETag(r.Header.Get("If-None-Match"), etag) {
			w.WriteHeader(http.StatusNotModified)
			return
		}

		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write(body)
	})
}

// bodyCache memoises the marshalled JWKS and its ETag. /jwks is the
// hottest endpoint in the library — every RP validating a token hits
// it — so the marshal and the SHA-256 run only when the published key
// material actually changes.
//
// Invalidation rests on two properties of [internal/keys]:
//
//   - A [keys.Set] is immutable once [keys.NewSet] returns, and the
//     handler binds one for its lifetime, so the signing half of the
//     document is a constant. A key rotation replaces the whole OP
//     router (and with it this handler), never the contents of a live
//     Set.
//   - A [keys.EncryptionSet] is likewise immutable, but its published
//     view is clock-dependent: [keys.EncryptionSet.JWKS] drops entries
//     that have passed their retirement deadline. The live kid list is
//     therefore the only thing that can vary between two requests, and
//     keying the cache on it captures every such change exactly.
type bodyCache struct {
	set *keys.Set
	enc *keys.EncryptionSet

	// current holds the most recently rendered document. The pointed-to
	// [cachedBody] is never mutated after publication, so a concurrent
	// reader either sees the previous rendering or the new one, never a
	// torn mix. Simultaneous misses may each render; they agree on the
	// result, so the redundant work is bounded and harmless.
	current atomic.Pointer[cachedBody]
}

// cachedBody is one immutable rendering of the JWKS document. key
// identifies the key material body was built from; body and etag MUST
// NOT be mutated once the value is published through [bodyCache.current].
type cachedBody struct {
	key  string
	body []byte
	etag string
}

// render returns the JWKS body and its ETag, reusing the memoised
// rendering when the live encryption kids are unchanged. The returned
// slice is shared with other in-flight requests and MUST NOT be
// mutated.
//
// The JWKS values only ever flow through type inference here. Naming
// the go-jose key type would make this package a second direct caller
// of the library, which the OP confines to internal/jose so every
// algorithm decision passes one gate.
func (c *bodyCache) render() ([]byte, string, error) {
	if c.enc == nil {
		// Nothing clock-dependent contributes to the document, so the
		// first rendering serves for the lifetime of the handler.
		if cur := c.current.Load(); cur != nil {
			return cur.body, cur.etag, nil
		}
		body, err := json.Marshal(c.set.JWKS())
		if err != nil {
			return nil, "", err
		}
		rendered := c.publish("", body)
		return rendered.body, rendered.etag, nil
	}

	// One call, reused for both the cache key and the body: asking the
	// set twice would let the clock cross a retirement deadline
	// between the two readings and pair a body with the wrong key.
	enc := c.enc.JWKS()

	// The cache identity is the live kid list. Each kid is
	// length-prefixed so no two distinct lists collide on the same
	// string, whatever characters a kid contains.
	var ident strings.Builder
	for _, k := range enc.Keys {
		ident.WriteString(strconv.Itoa(len(k.KeyID)))
		ident.WriteByte(':')
		ident.WriteString(k.KeyID)
	}
	key := ident.String()
	if cur := c.current.Load(); cur != nil && cur.key == key {
		return cur.body, cur.etag, nil
	}

	// Signing keys first so RPs scanning in order encounter them
	// before the use=enc entries. Set.JWKS returns a full-capacity
	// slice, so the append allocates rather than writing into shared
	// backing storage.
	merged := c.set.JWKS()
	merged.Keys = append(merged.Keys, enc.Keys...)
	body, err := json.Marshal(merged)
	if err != nil {
		return nil, "", err
	}
	rendered := c.publish(key, body)
	return rendered.body, rendered.etag, nil
}

// publish memoises one rendering and returns it. The stored value is
// never mutated afterwards, so a concurrent reader sees either this
// rendering or the previous one, never a torn mix.
func (c *bodyCache) publish(key string, body []byte) *cachedBody {
	rendered := &cachedBody{key: key, body: body, etag: computeETag(body)}
	c.current.Store(rendered)
	return rendered
}

// computeETag returns the strong ETag for body. The hash covers the
// full marshalled JWKS so any kid/key change rolls the value, even if
// no other byte differs.
func computeETag(body []byte) string {
	sum := sha256.Sum256(body)
	return `"` + hex.EncodeToString(sum[:]) + `"`
}

// matchesETag reports whether any entity-tag in If-None-Match matches
// etag under the weak comparison function RFC 9110 §8.8.3.2 mandates
// for that header: only the opaque quoted portion participates, so a
// validator an intermediary weakened to W/"..." still matches the
// strong tag we emit. "*" matches every representation.
//
// Entries that are not syntactically valid entity-tags are skipped
// rather than compared, so a malformed list cannot match by accident.
func matchesETag(ifNoneMatch, etag string) bool {
	field := strings.TrimSpace(ifNoneMatch)
	if field == "" {
		return false
	}
	// RFC 9110 §8.8.3.2 wildcard.
	if field == "*" {
		return true
	}
	want, ok := opaqueTag(etag)
	if !ok {
		return false
	}
	// Multiple validators are comma-separated; we accept any match.
	for _, raw := range strings.Split(field, ",") {
		got, ok := opaqueTag(strings.TrimSpace(raw))
		if ok && got == want {
			return true
		}
	}
	return false
}

// opaqueTag returns the quoted opaque portion of one entity-tag,
// discarding the weakness indicator that the weak comparison function
// ignores. The indicator is matched case-sensitively as the RFC 9110
// §8.8.3 grammar spells it ("W/"), and the remainder must be a quoted
// string; anything else reports false.
func opaqueTag(entityTag string) (string, bool) {
	tag := strings.TrimPrefix(entityTag, "W/")
	if len(tag) < 2 || tag[0] != '"' || tag[len(tag)-1] != '"' {
		return "", false
	}
	return tag, true
}
