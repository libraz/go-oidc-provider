package discovery

import (
	"encoding/json"
	"net/http"
)

// CacheControl is the value the handler stamps on every successful
// response. It targets a 1-hour cache with a 10-minute
// stale-while-revalidate window02-product-design.md §F.6.
const CacheControl = "public, max-age=3600, stale-while-revalidate=600"

// Handler returns an [http.Handler] that serves the OpenID Connect
// Discovery 1.0 metadata at /.well-known/openid-configuration. The
// document body is marshalled once and cached for the lifetime of the
// returned handler.
func Handler(doc Document) (http.Handler, error) {
	body, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", CacheControl)
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write(body)
	}), nil
}
