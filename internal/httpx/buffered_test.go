package httpx_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/httpx"
)

func TestBufferedWriterCommit(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		write      func(w http.ResponseWriter)
		wantStatus int
		wantBody   string
	}{
		{"body implies 200", func(w http.ResponseWriter) { _, _ = w.Write([]byte("ok")) }, http.StatusOK, "ok"},
		{"explicit status kept", func(w http.ResponseWriter) { w.WriteHeader(http.StatusTeapot); w.WriteHeader(http.StatusOK) }, http.StatusTeapot, ""},
		{"untouched uses default", func(http.ResponseWriter) {}, http.StatusInternalServerError, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			buf := httpx.NewBufferedWriter(http.StatusInternalServerError)
			buf.Header().Set("X-Test", "1")
			tc.write(buf)
			rec := httptest.NewRecorder()
			if err := buf.Commit(rec); err != nil {
				t.Fatalf("Commit: %v", err)
			}
			if rec.Code != tc.wantStatus || rec.Body.String() != tc.wantBody {
				t.Fatalf("got %d %q, want %d %q", rec.Code, rec.Body.String(), tc.wantStatus, tc.wantBody)
			}
			if rec.Header().Get("X-Test") != "1" {
				t.Fatalf("header not copied: %v", rec.Header())
			}
		})
	}
}

func TestBufferedWriterNothingLeaksBeforeCommit(t *testing.T) {
	t.Parallel()
	rec := httptest.NewRecorder()
	buf := httpx.NewBufferedWriter(http.StatusOK)
	buf.WriteHeader(http.StatusCreated)
	_, _ = buf.Write([]byte("x"))
	if rec.Body.Len() != 0 || len(rec.Header()) != 0 {
		t.Fatal("buffered writer wrote through before Commit")
	}
}
