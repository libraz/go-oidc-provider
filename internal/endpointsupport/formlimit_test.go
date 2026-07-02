package endpointsupport_test

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/endpointsupport"
	"github.com/libraz/go-oidc-provider/internal/httpx"
)

// TestMaxFormBytes_ConstantPin guards the documented 64 KiB cap; a
// regression that drops it to 0 (which would silently disable
// MaxBytesReader) fails this test.
func TestMaxFormBytes_ConstantPin(t *testing.T) {
	t.Parallel()
	if endpointsupport.MaxFormBytes != 64*1024 {
		t.Fatalf("MaxFormBytes=%d, want 65536 (64 KiB)", endpointsupport.MaxFormBytes)
	}
}

// TestMaxFormBytes_SharesHTTPXConstant confirms endpointsupport.MaxFormBytes
// aliases httpx.MaxFormBytes rather than declaring an independent copy of
// the 64 KiB value. Every OP endpoint that installs a body-size cap
// ultimately reads this one constant, so a regression that lets the two
// definitions drift apart is caught here rather than surfacing as a
// per-endpoint behavioral inconsistency.
func TestMaxFormBytes_SharesHTTPXConstant(t *testing.T) {
	t.Parallel()
	if endpointsupport.MaxFormBytes != httpx.MaxFormBytes {
		t.Fatalf("endpointsupport.MaxFormBytes=%d, httpx.MaxFormBytes=%d: want equal (single shared const)",
			endpointsupport.MaxFormBytes, httpx.MaxFormBytes)
	}
}

// TestLimitFormBody_RejectsOversize confirms the helper installs an
// [http.MaxBytesReader] cap that fires when the request body exceeds
// [MaxFormBytes].
func TestLimitFormBody_RejectsOversize(t *testing.T) {
	t.Parallel()
	body := strings.NewReader(strings.Repeat("A", endpointsupport.MaxFormBytes+1024))
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/whatever", body)
	rec := httptest.NewRecorder()
	endpointsupport.LimitFormBody(rec, req)

	// Read the body to its end; MaxBytesReader returns *http.MaxBytesError
	// once the cap is exceeded.
	_, err := io.ReadAll(req.Body)
	if err == nil {
		t.Fatalf("read after LimitFormBody: want MaxBytesError, got nil")
	}
	var maxErr *http.MaxBytesError
	if !errors.As(err, &maxErr) {
		t.Fatalf("read after LimitFormBody: got %v (%T), want *http.MaxBytesError", err, err)
	}
}

// TestLimitFormBody_AdmitsUnderCap confirms a body strictly inside the
// cap reads through unchanged.
func TestLimitFormBody_AdmitsUnderCap(t *testing.T) {
	t.Parallel()
	want := strings.Repeat("A", 1024)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/whatever", strings.NewReader(want))
	rec := httptest.NewRecorder()
	endpointsupport.LimitFormBody(rec, req)
	got, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatalf("read after LimitFormBody: %v", err)
	}
	if string(got) != want {
		t.Fatalf("read after LimitFormBody: got %d bytes, want %d", len(got), len(want))
	}
}

// TestLimitFormBody_NilSafe confirms the helper tolerates a nil
// request body, response writer, or request — the caller never relies
// on a panic, the helper just returns silently.
func TestLimitFormBody_NilSafe(t *testing.T) {
	t.Parallel()
	endpointsupport.LimitFormBody(nil, nil)
	rec := httptest.NewRecorder()
	endpointsupport.LimitFormBody(rec, nil)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/whatever", http.NoBody)
	endpointsupport.LimitFormBody(nil, req)
}
