package httpx_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/httpx"
)

func TestWriteJSON_HappyPath(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	body := map[string]any{"foo": "bar", "n": 7}
	if err := httpx.WriteJSON(rec, http.StatusOK, body); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status=%d want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != httpx.JSONContentType {
		t.Errorf("Content-Type=%q", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control=%q want no-store", got)
	}
	var decoded map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if decoded["foo"] != "bar" {
		t.Errorf("foo=%v want bar", decoded["foo"])
	}
	if got := rec.Header().Get("Content-Length"); got == "" {
		t.Error("Content-Length missing")
	}
}

func TestWriteJSON_StatusEchoes(t *testing.T) {
	t.Parallel()

	cases := []int{
		http.StatusOK,
		http.StatusBadRequest,
		http.StatusUnauthorized,
		http.StatusForbidden,
		http.StatusInternalServerError,
	}
	for _, status := range cases {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			t.Parallel()
			rec := httptest.NewRecorder()
			if err := httpx.WriteJSON(rec, status, map[string]int{"x": 1}); err != nil {
				t.Fatalf("WriteJSON: %v", err)
			}
			if rec.Code != status {
				t.Errorf("status=%d want %d", rec.Code, status)
			}
		})
	}
}

// unmarshallable forces json.Marshal to fail.
type unmarshallable struct{ Ch chan int }

func TestWriteJSON_MarshalFailureFallsBackToServerError(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	err := httpx.WriteJSON(rec, http.StatusOK, unmarshallable{Ch: make(chan int)})
	if err == nil {
		t.Fatal("WriteJSON returned nil error for unmarshallable body")
	}
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status=%d want 500", rec.Code)
	}
	var body httpx.ErrorBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode fallback body: %v", err)
	}
	if body.Error != "server_error" {
		t.Errorf("error=%q want server_error", body.Error)
	}
}

func TestWriteError_OAuthShape(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	if err := httpx.WriteError(rec, http.StatusBadRequest, "invalid_request", "missing client_id"); err != nil {
		t.Fatalf("WriteError: %v", err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status=%d want 400", rec.Code)
	}
	var body httpx.ErrorBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Error != "invalid_request" {
		t.Errorf("error=%q", body.Error)
	}
	if body.ErrorDescription != "missing client_id" {
		t.Errorf("description=%q", body.ErrorDescription)
	}
}

func TestWriteError_NoStoreHeader(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	if err := httpx.WriteError(rec, http.StatusBadRequest, "invalid_grant", ""); err != nil {
		t.Fatalf("WriteError: %v", err)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control=%q want no-store (errors must not be cached)", got)
	}
}

func TestWriteOAuthBearerChallenge_HeaderShape(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	err := httpx.WriteOAuthBearerChallenge(
		rec,
		http.StatusUnauthorized,
		"invalid_token",
		"token expired",
		"https://op.example.com",
		"openid profile",
	)
	if err != nil {
		t.Fatalf("WriteOAuthBearerChallenge: %v", err)
	}
	got := rec.Header().Get("WWW-Authenticate")
	want := `Bearer realm="https://op.example.com", error="invalid_token", error_description="token expired", scope="openid profile"`
	if got != want {
		t.Errorf("WWW-Authenticate=%q\nwant %q", got, want)
	}
}

func TestWriteOAuthBearerChallenge_OmitsEmptyParameters(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	err := httpx.WriteOAuthBearerChallenge(rec, http.StatusUnauthorized, "invalid_token", "", "", "")
	if err != nil {
		t.Fatalf("WriteOAuthBearerChallenge: %v", err)
	}
	got := rec.Header().Get("WWW-Authenticate")
	if got != `Bearer error="invalid_token"` {
		t.Errorf("WWW-Authenticate=%q want only error= parameter", got)
	}
}

func TestWriteOAuthBearerChallenge_QuoteEscape(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	// Description with a quote and backslash must be escaped.
	err := httpx.WriteOAuthBearerChallenge(rec, http.StatusUnauthorized, "invalid_token", `oh "no" \backslash`, "", "")
	if err != nil {
		t.Fatalf("WriteOAuthBearerChallenge: %v", err)
	}
	got := rec.Header().Get("WWW-Authenticate")
	if !contains(got, `\"no\"`) {
		t.Errorf("WWW-Authenticate=%q must escape inner quotes", got)
	}
	if !contains(got, `\\backslash`) {
		t.Errorf("WWW-Authenticate=%q must escape backslash", got)
	}
}

// contains is a tiny strings.Contains substitute that avoids pulling the
// strings import into the test file when only one call site needs it.
func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}

// TestWriteJSON_UsableInsideHandler asserts WriteJSON works as the response
// half of a real net/http handler: we boot an httptest server, hit it with
// a request-scoped context, and inspect the round-trip.
func TestWriteJSON_UsableInsideHandler(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = httpx.WriteJSON(w, http.StatusTeapot, map[string]string{"hello": "world"})
	}))
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, http.NoBody)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusTeapot {
		t.Errorf("status=%d", resp.StatusCode)
	}
	if errors.Is(err, http.ErrAbortHandler) {
		t.Error("unexpected abort")
	}
}
