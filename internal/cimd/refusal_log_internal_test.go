package cimd

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
)

const (
	refusedID     = "https://mcp-client.example/client.json"
	testOptInName = "op.WithAllowPrivateNetworkCIMD()"
)

func loopbackLookup(context.Context, string) ([]net.IPAddr, error) {
	return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
}

func TestGetClient_DenyListRefusalLogsOneWarn(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	h := newHarness(t, func(c *Config) {
		c.AllowPrivate = false
		c.OptIn = testOptInName
		c.Logger = slog.New(slog.NewJSONHandler(&buf, nil))
		c.lookupHook = loopbackLookup
	})

	if _, err := h.store.GetClient(context.Background(), refusedID); err == nil {
		t.Fatal("GetClient of a loopback-resolving id succeeded")
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("log records=%d want 1: %s", len(lines), buf.String())
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if rec["level"] != "WARN" || rec["msg"] != "outbound fetch refused by the private-network deny-list" {
		t.Errorf("level=%v msg=%v", rec["level"], rec["msg"])
	}
	if rec["fetch"] != "client_id_metadata" || rec["client_id"] != refusedID {
		t.Errorf("fetch=%v client_id=%v", rec["fetch"], rec["client_id"])
	}
	if s, _ := rec["err"].(string); !strings.Contains(s, testOptInName) {
		t.Errorf("err=%v want the opt-in %q", rec["err"], testOptInName)
	}
}

func TestGetClient_NilLoggerDoesNotPanicOnRefusal(t *testing.T) {
	t.Parallel()
	h := newHarness(t, func(c *Config) {
		c.AllowPrivate = false
		c.lookupHook = loopbackLookup
	})
	if _, err := h.store.GetClient(context.Background(), refusedID); err == nil {
		t.Fatal("GetClient of a loopback-resolving id succeeded")
	}
}

func TestGetClient_NonDenyListFailureDoesNotLog(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	srv := newDocServer(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) })
	h := newHarness(t, func(c *Config) { c.Logger = slog.New(slog.NewJSONHandler(&buf, nil)) })

	if _, err := h.store.GetClient(context.Background(), srv.id()); err == nil {
		t.Fatal("404 document resolved")
	}
	if buf.Len() != 0 {
		t.Fatalf("unexpected log output: %s", buf.String())
	}
}
