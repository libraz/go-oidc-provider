package parendpoint

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/jar"
	"github.com/libraz/go-oidc-provider/internal/rpjwks"
)

// TestWriteJARError_KeySourceFaultIsServerError pins that a JWKS capacity or
// transient fault during request-object verification answers 503
// server_error, while a client-side JAR failure stays a 400.
func TestWriteJARError_KeySourceFaultIsServerError(t *testing.T) {
	t.Parallel()

	fault := fmt.Errorf("%w: %w", jar.ErrKeySourceUnavailable, &rpjwks.TransientError{Cause: rpjwks.ErrOverloaded})
	rec := httptest.NewRecorder()
	writeJARError(rec, fault)
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), `"error":"server_error"`) {
		t.Fatalf("key-source fault: status=%d body=%s, want 503 server_error", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	writeJARError(rec, jar.ErrSigInvalid)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("signature failure: status=%d body=%s, want 400", rec.Code, rec.Body.String())
	}
}
