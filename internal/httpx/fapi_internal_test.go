package httpx

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestInteractionIDMiddleware_OmitsHeaderWhenGenerationFails(t *testing.T) {
	t.Parallel()
	called := false
	h := interactionIDMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}), func() string { return "" })
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if !called {
		t.Fatal("next handler not invoked")
	}
	if _, present := rec.Header()[http.CanonicalHeaderKey(FAPIInteractionIDHeader)]; present {
		t.Errorf("header set despite generation failure: %q", rec.Header().Values(FAPIInteractionIDHeader))
	}
}
