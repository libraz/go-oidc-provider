package httpx_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/httpx"
)

func newReq(tb testing.TB, method string) *http.Request {
	tb.Helper()
	return httptest.NewRequestWithContext(context.Background(), method, "/x", http.NoBody)
}

func TestEnforceMethod_Accepts(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	if !httpx.EnforceMethod(rec, newReq(t, http.MethodPost), http.MethodPost) {
		t.Error("POST rejected when POST is allowed")
	}
}

func TestEnforceMethod_HeadAcceptedWhenGetAllowed(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	if !httpx.EnforceMethod(rec, newReq(t, http.MethodHead), http.MethodGet) {
		t.Error("HEAD rejected when GET is allowed")
	}
}

func TestEnforceMethod_RejectsMismatch(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	if httpx.EnforceMethod(rec, newReq(t, http.MethodDelete), http.MethodGet, http.MethodPost) {
		t.Error("DELETE accepted by GET/POST endpoint")
	}
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status=%d want 405", rec.Code)
	}
	allow := rec.Header().Get("Allow")
	if allow != "GET, HEAD, POST" {
		t.Errorf("Allow=%q want GET, HEAD, POST", allow)
	}
	if got := rec.Body.String(); got != "method not allowed\n" {
		t.Errorf("body=%q want plain-text method not allowed", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control=%q want no-store", got)
	}
	if got := rec.Header().Get("Pragma"); got != "no-cache" {
		t.Errorf("Pragma=%q want no-cache", got)
	}
}

func TestEnforceMethod_AllowHeaderWithoutGet(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	httpx.EnforceMethod(rec, newReq(t, http.MethodGet), http.MethodPost, http.MethodPut)
	if got := rec.Header().Get("Allow"); got != "POST, PUT" {
		t.Errorf("Allow=%q want POST, PUT", got)
	}
}

func TestEnforceMethod_PreservesArgumentOrder(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	// First arg is treated as canonical for OPTIONS / OAuth-style flows.
	httpx.EnforceMethod(rec, newReq(t, http.MethodTrace), http.MethodPost, http.MethodGet)
	if got := rec.Header().Get("Allow"); got != "POST, GET, HEAD" {
		t.Errorf("Allow=%q want POST, GET, HEAD", got)
	}
}

func TestMethodNotAllowed_OmitsEmptyAllow(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	httpx.MethodNotAllowed(rec, "")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("status=%d want 405", rec.Code)
	}
	if _, ok := rec.Header()["Allow"]; ok {
		t.Errorf("Allow header set for an empty method list: %q", rec.Header().Get("Allow"))
	}
}

func TestStampNoStore_SetsBothHeaders(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	httpx.StampNoStore(rec)
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control=%q want no-store", got)
	}
	if got := rec.Header().Get("Pragma"); got != "no-cache" {
		t.Errorf("Pragma=%q want no-cache", got)
	}
}
