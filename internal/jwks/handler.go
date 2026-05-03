package jwks

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/libraz/go-oidc-provider/internal/keys"
)

// CacheControl is the value the handler stamps on every successful
// response when no key rotation is currently in progress. It targets a
// 24-hour cache with a 1-hour stale-while-revalidate window, which
// lets RP caches absorb a normal day of traffic without repeatedly
// hitting the OP.
const CacheControl = "public, max-age=86400, stale-while-revalidate=3600"

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
// set after registration.
//
// The handler emits an ETag computed as the lowercase hex SHA-256 of
// the marshalled JSON body, wrapped in double quotes per RFC 7232
// §2.3 (strong validator). Callers presenting a matching value in
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
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		jwks := set.JWKS()
		if opts.EncryptionSet != nil {
			enc := opts.EncryptionSet.JWKS()
			jwks.Keys = append(jwks.Keys, enc.Keys...)
		}
		body, err := json.Marshal(jwks)
		if err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		etag := computeETag(body)
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

// computeETag returns the strong ETag for body. The hash covers the
// full marshalled JWKS so any kid/key change rolls the value, even if
// no other byte differs.
func computeETag(body []byte) string {
	sum := sha256.Sum256(body)
	return `"` + hex.EncodeToString(sum[:]) + `"`
}

// matchesETag reports whether any token in If-None-Match equals etag.
// The comparison is byte-equal on the quoted form per RFC 7232 §3.2;
// "*" matches every representation. Weak validators (W/"...") are
// treated as non-matching because the ETag we emit is strong.
func matchesETag(ifNoneMatch, etag string) bool {
	if ifNoneMatch == "" {
		return false
	}
	// RFC 7232 §3.2 wildcard.
	if ifNoneMatch == "*" {
		return true
	}
	// Multiple validators are comma-separated; we accept any match.
	for _, raw := range strings.Split(ifNoneMatch, ",") {
		if strings.TrimSpace(raw) == etag {
			return true
		}
	}
	return false
}
