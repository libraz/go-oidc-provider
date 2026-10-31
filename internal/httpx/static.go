package httpx

import (
	"encoding/json"
	"net/http"
)

// StaticDocumentCacheControl is the Cache-Control value for the metadata
// documents the OP serves unchanged for long stretches (discovery, protected
// resource metadata). It targets a 1-hour cache with a 10-minute
// stale-while-revalidate window: relying parties cut their round-trips
// without being pinned to a stale document for long.
const StaticDocumentCacheControl = "public, max-age=3600, stale-while-revalidate=600"

// StaticJSONHandler returns a read-only [http.Handler] that serves doc as
// JSON. The body is marshalled once and reused; the handler answers GET and
// HEAD only (other methods get the [EnforceMethod] 405) and stamps
// cacheControl on every successful response.
func StaticJSONHandler(doc any, cacheControl string) (http.Handler, error) {
	body, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !EnforceMethod(w, r, http.MethodGet) {
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", cacheControl)
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write(body)
	}), nil
}
