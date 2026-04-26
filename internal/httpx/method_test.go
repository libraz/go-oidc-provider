package httpx_test

import (
	"context"
	"encoding/json"
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
	var body httpx.ErrorBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Error != "method_not_allowed" {
		t.Errorf("error=%q want method_not_allowed", body.Error)
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
