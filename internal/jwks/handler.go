package jwks

import (
	"encoding/json"
	"net/http"

	"github.com/libraz/go-oidc-provider/internal/keys"
)

// CacheControl is the value the handler stamps on every successful
// response. It targets a 24-hour cache with a 1-hour stale-while-revalidate
// window per docs/plans/002-product-design.md §F.6, which lets RP caches
// absorb a key rotation without taking the OP out of the verification path.
const CacheControl = "public, max-age=86400, stale-while-revalidate=3600"

// Handler returns an [http.Handler] that serves the public JWKS for set.
// The returned handler is safe for concurrent use; callers MUST NOT mutate
// set after registration.
func Handler(set *keys.Set) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		jwks := set.JWKS()
		body, err := json.Marshal(jwks)
		if err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/jwk-set+json")
		w.Header().Set("Cache-Control", CacheControl)
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write(body)
	})
}
