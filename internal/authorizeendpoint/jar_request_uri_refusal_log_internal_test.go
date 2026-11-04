package authorizeendpoint

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFetchJARRequestURI_DenyListRefusalLogsOneWarn(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	deps := resolveDeps(Deps{Logger: slog.New(slog.NewJSONHandler(&buf, nil))})
	const uri = "https://127.0.0.1/request.jwt"

	rec := httptest.NewRecorder()
	if _, ok := fetchJARRequestURI(rec, jarFetchRequest(), deps, fakeClient(uri), uri, ""); ok {
		t.Fatal("fetch of a loopback request_uri succeeded")
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("log records=%d want 1: %s", len(lines), buf.String())
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["level"] != "WARN" || got["msg"] != "outbound fetch refused by the private-network deny-list" {
		t.Errorf("level=%v msg=%v", got["level"], got["msg"])
	}
	if got["fetch"] != "request_uri" || got["client_id"] != "fake-client" {
		t.Errorf("fetch=%v client_id=%v", got["fetch"], got["client_id"])
	}
	if s, _ := got["err"].(string); !strings.Contains(s, jarPrivateNetworkOptIn) {
		t.Errorf("err=%v want the opt-in %q", got["err"], jarPrivateNetworkOptIn)
	}

	// A replay inside the negative window is answered from the cache.
	if _, ok := fetchJARRequestURI(httptest.NewRecorder(), jarFetchRequest(), deps, fakeClient(uri), uri, ""); ok {
		t.Fatal("replayed fetch succeeded")
	}
	if n := strings.Count(strings.TrimSpace(buf.String()), "\n") + 1; n != 1 {
		t.Fatalf("records after replay=%d want 1", n)
	}
}

func TestFetchJARRequestURI_NilLoggerDoesNotPanicOnRefusal(t *testing.T) {
	t.Parallel()
	deps := jarFetchDeps(false)
	const uri = "https://127.0.0.1/request.jwt"
	if _, ok := fetchJARRequestURI(httptest.NewRecorder(), jarFetchRequest(), deps, fakeClient(uri), uri, ""); ok {
		t.Fatal("fetch of a loopback request_uri succeeded")
	}
}

func TestFetchJARRequestURI_NonDenyListFailureDoesNotLog(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	deps := resolveDeps(Deps{AllowPrivateNetworkJAR: true, Logger: slog.New(slog.NewJSONHandler(&buf, nil))})

	if _, ok := fetchJARRequestURI(httptest.NewRecorder(), jarFetchRequest(), deps, fakeClient(srv.URL), srv.URL, ""); ok {
		t.Fatal("404 request_uri fetched")
	}
	if buf.Len() != 0 {
		t.Fatalf("unexpected log output: %s", buf.String())
	}
}
