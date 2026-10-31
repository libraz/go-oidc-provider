package httpx_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/httpx"
)

func TestStaticJSONHandler_ServesGetAndHead(t *testing.T) {
	t.Parallel()

	h, err := httpx.StaticJSONHandler(map[string]string{"issuer": "https://op.example"}, httpx.StaticDocumentCacheControl)
	if err != nil {
		t.Fatalf("StaticJSONHandler: %v", err)
	}

	get := httptest.NewRecorder()
	h.ServeHTTP(get, newReq(t, http.MethodGet))
	if get.Code != http.StatusOK {
		t.Fatalf("GET status=%d want 200", get.Code)
	}
	if got := get.Body.String(); got != `{"issuer":"https://op.example"}` {
		t.Errorf("GET body=%q", got)
	}
	if got := get.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type=%q want application/json", got)
	}
	if got := get.Header().Get("Cache-Control"); got != httpx.StaticDocumentCacheControl {
		t.Errorf("Cache-Control=%q want %q", got, httpx.StaticDocumentCacheControl)
	}

	head := httptest.NewRecorder()
	h.ServeHTTP(head, newReq(t, http.MethodHead))
	if head.Code != http.StatusOK || head.Body.Len() != 0 {
		t.Errorf("HEAD status=%d bodyLen=%d want 200 and empty body", head.Code, head.Body.Len())
	}
	if got := head.Header().Get("Cache-Control"); got != httpx.StaticDocumentCacheControl {
		t.Errorf("HEAD Cache-Control=%q", got)
	}
}

func TestStaticJSONHandler_RejectsOtherMethods(t *testing.T) {
	t.Parallel()

	h, err := httpx.StaticJSONHandler(struct{}{}, "max-age=1")
	if err != nil {
		t.Fatalf("StaticJSONHandler: %v", err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, newReq(t, http.MethodPost))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status=%d want 405", rec.Code)
	}
	if got := rec.Header().Get("Allow"); got != "GET, HEAD" {
		t.Errorf("Allow=%q want GET, HEAD", got)
	}
}

func TestStaticJSONHandler_MarshalFailure(t *testing.T) {
	t.Parallel()

	if _, err := httpx.StaticJSONHandler(make(chan int), "max-age=1"); err == nil {
		t.Fatal("expected a marshal error for an unmarshalable document")
	}
}
