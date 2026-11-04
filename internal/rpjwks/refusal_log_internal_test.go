package rpjwks

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testOptIn = "op.WithAllowPrivateNetwork(op.OutboundJWKS)"

// logRecords decodes the JSON lines buf holds.
func logRecords(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("decode log line %q: %v", line, err)
		}
		out = append(out, rec)
	}
	return out
}

func TestFetch_DenyListRefusalLogsOneWarn(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	f := New(Config{
		Clock:  testClock(),
		OptIn:  testOptIn,
		Logger: slog.New(slog.NewJSONHandler(&buf, nil)),
	})

	if _, err := f.Fetch(context.Background(), "https://127.0.0.1/jwks"); err == nil {
		t.Fatal("fetch of a loopback target succeeded")
	}
	recs := logRecords(t, &buf)
	if len(recs) != 1 {
		t.Fatalf("log records=%d want 1: %s", len(recs), buf.String())
	}
	rec := recs[0]
	if rec["level"] != "WARN" || rec["msg"] != "outbound fetch refused by the private-network deny-list" {
		t.Errorf("level=%v msg=%v", rec["level"], rec["msg"])
	}
	if rec["fetch"] != "jwks_uri" {
		t.Errorf("fetch=%v want jwks_uri", rec["fetch"])
	}
	if _, ok := rec["client_id"]; ok {
		t.Errorf("client_id present on a fetch that does not know it: %v", rec["client_id"])
	}
	if s, _ := rec["err"].(string); !strings.Contains(s, testOptIn) {
		t.Errorf("err=%v want the opt-in %q", rec["err"], testOptIn)
	}
}

// TestFetch_DenyListRefusalLogsOncePerNegativeTTL pins that the record rides
// the cache loader: replays inside the negative window do not log again.
func TestFetch_DenyListRefusalLogsOncePerNegativeTTL(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	clock := testClock()
	f := New(Config{
		Clock:       clock,
		NegativeTTL: 5 * time.Second,
		OptIn:       testOptIn,
		Logger:      slog.New(slog.NewJSONHandler(&buf, nil)),
	})
	const uri = "https://127.0.0.1/jwks"

	for range 3 {
		if _, err := f.Fetch(context.Background(), uri); err == nil {
			t.Fatal("fetch of a loopback target succeeded")
		}
	}
	if n := len(logRecords(t, &buf)); n != 1 {
		t.Fatalf("records inside the negative window=%d want 1", n)
	}
	clock.now = clock.now.Add(6 * time.Second)
	if _, err := f.Fetch(context.Background(), uri); err == nil {
		t.Fatal("fetch of a loopback target succeeded")
	}
	if n := len(logRecords(t, &buf)); n != 2 {
		t.Fatalf("records after the window=%d want 2", n)
	}
}

func TestFetch_NilLoggerDoesNotPanicOnRefusal(t *testing.T) {
	t.Parallel()
	f := New(Config{Clock: testClock()})
	if _, err := f.Fetch(context.Background(), "https://127.0.0.1/jwks"); err == nil {
		t.Fatal("fetch of a loopback target succeeded")
	}
}

func TestFetch_NonDenyListFailureDoesNotLog(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	var buf bytes.Buffer
	f := newTestFetcher(t, Config{
		Clock:  testClock(),
		Logger: slog.New(slog.NewJSONHandler(&buf, nil)),
	})

	if _, err := f.Fetch(context.Background(), srv.URL); err == nil {
		t.Fatal("404 fetch succeeded")
	}
	if buf.Len() != 0 {
		t.Fatalf("unexpected log output: %s", buf.String())
	}
}
