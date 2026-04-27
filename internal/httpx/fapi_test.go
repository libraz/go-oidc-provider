package httpx_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/httpx"
)

var uuidV4Re = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestNewInteractionID_MatchesUUIDv4Shape(t *testing.T) {
	t.Parallel()

	for range [128]struct{}{} {
		got := httpx.NewInteractionID()
		if !uuidV4Re.MatchString(got) {
			t.Fatalf("NewInteractionID() = %q, want UUIDv4", got)
		}
	}
}

func TestInteractionIDMiddleware_EchoesClientHeader(t *testing.T) {
	t.Parallel()

	want := "0123abcd-4567-89ef-0123-456789abcdef"
	handler := httpx.InteractionIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody)
	req.Header.Set(httpx.FAPIInteractionIDHeader, want)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if got := rec.Header().Get(httpx.FAPIInteractionIDHeader); got != want {
		t.Errorf("response %s = %q, want %q (must echo client-supplied value verbatim)",
			httpx.FAPIInteractionIDHeader, got, want)
	}
}

func TestInteractionIDMiddleware_GeneratesWhenAbsent(t *testing.T) {
	t.Parallel()

	handler := httpx.InteractionIDMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", http.NoBody)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	got := rec.Header().Get(httpx.FAPIInteractionIDHeader)
	if got == "" {
		t.Fatal("middleware did not stamp x-fapi-interaction-id when client omitted it")
	}
	if !uuidV4Re.MatchString(got) {
		t.Errorf("generated %s = %q, want UUIDv4 shape", httpx.FAPIInteractionIDHeader, got)
	}
}
