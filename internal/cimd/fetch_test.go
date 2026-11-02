//nolint:testpackage // white-box: drives documentTTL and the unexported Config seams.
package cimd

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/auditevent"
	"github.com/libraz/go-oidc-provider/op/store"
)

// paddedDocument returns a valid document for id padded to exactly size bytes.
func paddedDocument(t *testing.T, id string, size int) []byte {
	t.Helper()
	base := documentFor(id, map[string]any{"pad": ""})
	pad := size - len(base)
	if pad < 0 {
		t.Fatalf("base document is %d bytes, larger than %d", len(base), size)
	}
	return documentFor(id, map[string]any{"pad": strings.Repeat("x", pad)})
}

func TestGetClient_FetchFailureReasons(t *testing.T) {
	t.Parallel()

	jsonBody := func(body func(id string) string) func(http.ResponseWriter, *http.Request) {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body(requestURL(r))))
		}
	}
	cases := []struct {
		name     string
		handle   func(http.ResponseWriter, *http.Request)
		reason   string
		wantCode string
	}{
		{"not found", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) }, reasonStatus, ""},
		{"server error", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) }, reasonStatus, ""},
		{"302 not followed", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://"+r.Host+"/elsewhere.json", http.StatusFound) //nolint:gosec // G710: test server redirecting to itself.
		}, reasonStatus, ""},
		{"301 not followed", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://"+r.Host+"/elsewhere.json", http.StatusMovedPermanently) //nolint:gosec // G710: test server redirecting to itself.
		}, reasonStatus, ""},
		{"2xx other than 200", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write(documentFor(requestURL(r), nil))
		}, reasonStatus, ""},
		{"text/plain", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write(documentFor(requestURL(r), nil))
		}, reasonContentType, ""},
		{"missing content-type", func(w http.ResponseWriter, r *http.Request) {
			w.Header()["Content-Type"] = nil
			_, _ = w.Write(documentFor(requestURL(r), nil))
		}, reasonContentType, ""},
		{"5121 bytes", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(paddedDocument(t, requestURL(r), maxDocumentBytes+1))
		}, reasonTooLarge, ""},
		{"truncated JSON", jsonBody(func(string) string { return `{"client_id":` }), reasonJSON, ""},
		{"empty body", jsonBody(func(string) string { return `` }), reasonJSON, ""},
		{"empty object", jsonBody(func(string) string { return `{}` }), reasonValidation, "invalid_client_metadata"},
		{"array root", jsonBody(func(string) string { return `[]` }), reasonValidation, "invalid_client_metadata"},
		{"number root", jsonBody(func(string) string { return `42` }), reasonValidation, "invalid_client_metadata"},
		{"client_id trailing slash", jsonBody(func(id string) string {
			return string(documentFor(id+"/", nil))
		}), reasonValidation, "invalid_client_metadata"},
		{"redirect_uris missing", jsonBody(func(id string) string {
			return `{"client_id":"` + id + `"}`
		}), reasonValidation, "invalid_redirect_uri"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := newDocServer(t, tc.handle)
			h := newHarness(t, nil)

			_, err := h.store.GetClient(context.Background(), srv.id())
			if !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("err=%v, want ErrNotFound", err)
			}
			failed := h.rec.named(auditevent.AuditCIMDFetchFailed)
			if len(failed) != 1 {
				t.Fatalf("cimd.fetch_failed events=%d, want 1", len(failed))
			}
			ev := failed[0]
			if ev.ClientID != srv.id() || ev.Extras["reason"] != tc.reason {
				t.Fatalf("event client_id=%q reason=%v, want %q / %q", ev.ClientID, ev.Extras["reason"], srv.id(), tc.reason)
			}
			code, hasCode := ev.Extras["error_code"]
			if tc.wantCode == "" && hasCode {
				t.Fatalf("error_code=%v on a %s failure, want absent", code, tc.reason)
			}
			if tc.wantCode != "" && code != tc.wantCode {
				t.Fatalf("error_code=%v, want %q", code, tc.wantCode)
			}
			if n := srv.hits.Load(); n != 1 {
				t.Fatalf("hits=%d, want 1 (no redirect followed)", n)
			}
		})
	}
}

func TestGetClient_AcceptedContentTypes(t *testing.T) {
	t.Parallel()
	for _, ct := range []string{"application/json", "application/json; charset=utf-8", "application/oauth-client-id+json"} {
		t.Run(ct, func(t *testing.T) {
			t.Parallel()
			srv := newDocServer(t, serveDocument(nil, http.Header{"Content-Type": {ct}}))
			h := newHarness(t, nil)
			if _, err := h.store.GetClient(context.Background(), srv.id()); err != nil {
				t.Fatalf("GetClient with Content-Type %q: %v", ct, err)
			}
		})
	}
}

func TestGetClient_BodyAtCapIsAccepted(t *testing.T) {
	t.Parallel()
	srv := newDocServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(paddedDocument(t, requestURL(r), maxDocumentBytes))
	})
	h := newHarness(t, nil)
	if _, err := h.store.GetClient(context.Background(), srv.id()); err != nil {
		t.Fatalf("GetClient with a %d-byte document: %v", maxDocumentBytes, err)
	}
}

func TestGetClient_TimeoutIsNetworkFailure(t *testing.T) {
	t.Parallel()
	done := make(chan struct{})
	srv := newDocServer(t, func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-done:
		}
	})
	t.Cleanup(func() { close(done) }) // runs before srv.Close (LIFO).
	h := newHarness(t, func(c *Config) { c.timeout = 100 * time.Millisecond })

	_, err := h.store.GetClient(context.Background(), srv.id())
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("err=%v, want ErrNotFound", err)
	}
	failed := h.rec.named(auditevent.AuditCIMDFetchFailed)
	if len(failed) != 1 || failed[0].Extras["reason"] != reasonNetwork {
		t.Fatalf("cimd.fetch_failed events=%+v, want one with reason network", failed)
	}
	// A timed-out fetch is negative-cached like any other failure.
	if _, err := h.store.GetClient(context.Background(), srv.id()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("second GetClient err=%v, want ErrNotFound", err)
	}
	if n := srv.hits.Load(); n != 1 {
		t.Fatalf("hits=%d, want 1 (timeout negative-cached)", n)
	}
}

// countingListener is a loopback TCP listener that counts accepted
// connections and closes each at once.
func countingListener(t *testing.T) (port string, accepts *atomic.Int32) {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	accepts = new(atomic.Int32)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepts.Add(1)
			_ = conn.Close()
		}
	}()
	_, port, _ = net.SplitHostPort(ln.Addr().String())
	return port, accepts
}

// TestGetClient_LoopbackRefusedWithoutAllowPrivate drives the SSRF gate on
// the client_id path: a public https name resolving to loopback is refused
// before any connection when the dev opt-in is off.
func TestGetClient_LoopbackRefusedWithoutAllowPrivate(t *testing.T) {
	t.Parallel()
	var lookups atomic.Int32
	h := newHarness(t, func(c *Config) {
		c.AllowPrivate = false
		c.lookupHook = func(context.Context, string) ([]net.IPAddr, error) {
			lookups.Add(1)
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
		}
	})
	const id = "https://mcp-client.example/client.json"

	_, err := h.store.GetClient(context.Background(), id)
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("err=%v, want ErrNotFound", err)
	}
	if lookups.Load() == 0 {
		t.Fatal("lookup hook never ran; the refusal did not come from the SSRF gate")
	}
	failed := h.rec.named(auditevent.AuditCIMDFetchFailed)
	if len(failed) != 1 || failed[0].Extras["reason"] != reasonNetwork {
		t.Fatalf("cimd.fetch_failed events=%+v, want one with reason network", failed)
	}
}

// TestGetClient_LoopbackLiteralOpensNoConnectionWithoutAllowPrivate asserts
// the gate refuses a loopback https target before connecting. The opted-in
// control proves the listener is reachable, so the zero count is not vacuous.
func TestGetClient_LoopbackLiteralOpensNoConnectionWithoutAllowPrivate(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name         string
		allowPrivate bool
	}{
		{name: "refused", allowPrivate: false},
		{name: "opted_in_control", allowPrivate: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			port, accepts := countingListener(t)
			h := newHarness(t, func(c *Config) { c.AllowPrivate = tc.allowPrivate })
			id := "https://127.0.0.1:" + port + "/client.json"

			if _, err := h.store.GetClient(context.Background(), id); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("err=%v, want ErrNotFound", err)
			}
			got := accepts.Load()
			if !tc.allowPrivate && got != 0 {
				t.Fatalf("accepted %d connections with the dev opt-in off, want 0", got)
			}
			if tc.allowPrivate && got == 0 {
				t.Fatal("control accepted no connection; the listener is unreachable and the gate assertion is vacuous")
			}
			failed := h.rec.named(auditevent.AuditCIMDFetchFailed)
			if len(failed) != 1 || failed[0].Extras["reason"] != reasonNetwork {
				t.Fatalf("cimd.fetch_failed events=%+v, want one with reason network", failed)
			}
		})
	}
}

func TestGetClient_HTTPLoopbackUnknownWithoutAllowPrivate(t *testing.T) {
	t.Parallel()
	srv := newDocServer(t, serveDocument(nil, nil))
	h := newHarness(t, func(c *Config) { c.AllowPrivate = false })

	if _, err := h.store.GetClient(context.Background(), srv.id()); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("err=%v, want ErrNotFound", err)
	}
	if n := srv.hits.Load(); n != 0 {
		t.Fatalf("hits=%d for an http id without the dev opt-in, want 0", n)
	}
	if n := h.rec.count(); n != 0 {
		t.Fatalf("audit events=%d, want 0 (URL rule failures are not audited)", n)
	}
}

func TestGetClient_HonoursDocumentTTL(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name         string
		cacheControl string
		fresh        time.Duration
	}{
		{"max-age inside bounds", "max-age=120", 120 * time.Second},
		{"max-age below floor", "max-age=10", minDocumentTTL},
		{"max-age above ceiling", "max-age=100000", maxDocumentTTL},
		{"no-store", "no-store, max-age=3600", minDocumentTTL},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := newDocServer(t, serveDocument(nil, http.Header{"Cache-Control": {tc.cacheControl}}))
			h := newHarness(t, nil)
			ctx := context.Background()

			if _, err := h.store.GetClient(ctx, srv.id()); err != nil {
				t.Fatalf("GetClient: %v", err)
			}
			h.clock.Advance(tc.fresh - time.Second)
			if _, err := h.store.GetClient(ctx, srv.id()); err != nil {
				t.Fatalf("GetClient before expiry: %v", err)
			}
			if n := srv.hits.Load(); n != 1 {
				t.Fatalf("hits=%d before %v elapsed, want 1", n, tc.fresh)
			}
			h.clock.Advance(time.Second)
			if _, err := h.store.GetClient(ctx, srv.id()); err != nil {
				t.Fatalf("GetClient after expiry: %v", err)
			}
			if n := srv.hits.Load(); n != 2 {
				t.Fatalf("hits=%d after %v elapsed, want 2", n, tc.fresh)
			}
		})
	}
}

func TestDocumentTTL(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	httpDate := func(d time.Duration) string { return now.Add(d).Format(http.TimeFormat) }

	cases := []struct {
		name   string
		header http.Header
		want   time.Duration
	}{
		{"no headers", http.Header{}, minDocumentTTL},
		{"max-age=0", http.Header{"Cache-Control": {"max-age=0"}}, minDocumentTTL},
		{"max-age=10", http.Header{"Cache-Control": {"max-age=10"}}, minDocumentTTL},
		{"max-age=3600", http.Header{"Cache-Control": {"public, max-age=3600"}}, time.Hour},
		{"max-age=100000", http.Header{"Cache-Control": {"max-age=100000"}}, maxDocumentTTL},
		{"max-age overflow", http.Header{"Cache-Control": {"max-age=99999999999999"}}, maxDocumentTTL},
		{"quoted max-age", http.Header{"Cache-Control": {`max-age="120"`}}, 120 * time.Second},
		{"upper-case directive", http.Header{"Cache-Control": {"MAX-AGE=120"}}, 120 * time.Second},
		{"first max-age wins", http.Header{"Cache-Control": {"max-age=120", "max-age=7200"}}, 120 * time.Second},
		{"no-store", http.Header{"Cache-Control": {"no-store, max-age=3600"}}, minDocumentTTL},
		{"no-cache", http.Header{"Cache-Control": {"max-age=3600, no-cache"}}, minDocumentTTL},
		{"no-cache with field", http.Header{"Cache-Control": {`no-cache="set-cookie", max-age=3600`}}, minDocumentTTL},
		{"private", http.Header{"Cache-Control": {"private, max-age=3600"}}, minDocumentTTL},
		{"Expires in two hours", http.Header{"Expires": {httpDate(2 * time.Hour)}}, 2 * time.Hour},
		{"Expires beyond ceiling", http.Header{"Expires": {httpDate(48 * time.Hour)}}, maxDocumentTTL},
		{"Expires in the past", http.Header{"Expires": {httpDate(-time.Hour)}}, minDocumentTTL},
		{"Expires invalid", http.Header{"Expires": {"0"}}, minDocumentTTL},
		{"max-age beats Expires", http.Header{"Cache-Control": {"max-age=120"}, "Expires": {httpDate(2 * time.Hour)}}, 120 * time.Second},
		{"malformed max-age falls back to Expires", http.Header{"Cache-Control": {"max-age=soon"}, "Expires": {httpDate(2 * time.Hour)}}, 2 * time.Hour},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := documentTTL(tc.header, now); got != tc.want {
				t.Fatalf("documentTTL(%v) = %v, want %v", tc.header, got, tc.want)
			}
		})
	}
}
