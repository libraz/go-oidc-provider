package authorizeendpoint

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/jar"
	"github.com/libraz/go-oidc-provider/internal/rpjwks"
)

// TestWriteJAREnvelopeError_KeySourceFaultIsServerError pins that a JWKS
// capacity or transient fault during request-object verification answers
// 503 server_error, the answer /authorize gives request_uri capacity
// exhaustion, rather than invalid_request_object.
func TestWriteJAREnvelopeError_KeySourceFaultIsServerError(t *testing.T) {
	t.Parallel()

	fault := fmt.Errorf("%w: %w", jar.ErrKeySourceUnavailable, &rpjwks.TransientError{Cause: rpjwks.ErrOverloaded})
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/authorize", http.NoBody)
	rec := httptest.NewRecorder()
	writeJAREnvelopeError(rec, r, resolved{}, fault, "st")
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), `"error":"server_error"`) {
		t.Fatalf("status=%d body=%s, want 503 server_error", rec.Code, rec.Body.String())
	}
}
