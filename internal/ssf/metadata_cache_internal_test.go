package ssf

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/httpx"
)

func TestMetadataIsCacheableStaticDocument(t *testing.T) {
	t.Parallel()
	h, err := NewMetadataHandler(metaDeps(testIssuer))
	if err != nil {
		t.Fatalf("NewMetadataHandler: %v", err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil))
	if got := w.Header().Get("Cache-Control"); got != httpx.StaticDocumentCacheControl {
		t.Errorf("Cache-Control = %q, want %q", got, httpx.StaticDocumentCacheControl)
	}
	if got := w.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q", got)
	}
}
