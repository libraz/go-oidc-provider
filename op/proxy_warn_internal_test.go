package op

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/proxy"
)

const untrustedForwardedWarning = "forwarded headers received but WithTrustedProxies is not configured"

// syncBuffer serialises writes so the slog handler can be shared by the
// middleware under test and the assertions.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) count(sub string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return strings.Count(b.buf.String(), sub)
}

func serveWithHeaders(t *testing.T, h http.Handler, headers map[string]string) {
	t.Helper()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "http://op.local/", nil)
	req.RemoteAddr = "203.0.113.5:9999"
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	h.ServeHTTP(httptest.NewRecorder(), req)
}

// TestUntrustedForwardedWarning_StartupLogger pins that the warning is wired
// to the startup logger: without WithLogger the operational logger discards
// everything, so the warning would be lost.
func TestUntrustedForwardedWarning_StartupLogger(t *testing.T) {
	t.Parallel()

	cfg := &config{}
	cfg.applyDefaults()
	if cfg.logger.Enabled(context.Background(), slog.LevelWarn) {
		t.Fatal("operational logger should discard without WithLogger")
	}
	if !cfg.startupLog().Enabled(context.Background(), slog.LevelWarn) {
		t.Fatal("startup logger must deliver warnings without WithLogger")
	}
}

func TestUntrustedForwardedWarning(t *testing.T) {
	t.Parallel()

	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})

	newHandler := func(t *testing.T, cidrs []string) (http.Handler, *syncBuffer) {
		t.Helper()
		trust, err := proxy.NewTrust(cidrs)
		if err != nil {
			t.Fatalf("proxy.NewTrust: %v", err)
		}
		buf := &syncBuffer{}
		logger := slog.New(slog.NewTextHandler(buf, nil))
		return wrapWithTrustedProxy(next, trust, logger), buf
	}

	t.Run("X-Forwarded-For warns once then stays silent", func(t *testing.T) {
		t.Parallel()
		h, buf := newHandler(t, nil)
		serveWithHeaders(t, h, map[string]string{"X-Forwarded-For": "198.51.100.1"})
		if got := buf.count(untrustedForwardedWarning); got != 1 {
			t.Fatalf("warnings after first request = %d, want 1", got)
		}
		serveWithHeaders(t, h, map[string]string{"X-Forwarded-For": "198.51.100.2"})
		if got := buf.count(untrustedForwardedWarning); got != 1 {
			t.Errorf("warnings after second request = %d, want 1", got)
		}
	})

	t.Run("X-Forwarded-Proto alone warns", func(t *testing.T) {
		t.Parallel()
		h, buf := newHandler(t, nil)
		serveWithHeaders(t, h, map[string]string{"X-Forwarded-Proto": "https"})
		if got := buf.count(untrustedForwardedWarning); got != 1 {
			t.Errorf("warnings = %d, want 1", got)
		}
	})

	t.Run("configured trust stays silent", func(t *testing.T) {
		t.Parallel()
		h, buf := newHandler(t, []string{"10.0.0.0/8"})
		serveWithHeaders(t, h, map[string]string{"X-Forwarded-For": "198.51.100.1"})
		if got := buf.count(untrustedForwardedWarning); got != 0 {
			t.Errorf("warnings = %d, want 0", got)
		}
	})

	t.Run("no forwarded headers stays silent", func(t *testing.T) {
		t.Parallel()
		h, buf := newHandler(t, nil)
		serveWithHeaders(t, h, nil)
		if got := buf.count(untrustedForwardedWarning); got != 0 {
			t.Errorf("warnings = %d, want 0", got)
		}
	})

	t.Run("X-Real-IP alone stays silent", func(t *testing.T) {
		t.Parallel()
		h, buf := newHandler(t, nil)
		serveWithHeaders(t, h, map[string]string{"X-Real-IP": "198.51.100.1"})
		if got := buf.count(untrustedForwardedWarning); got != 0 {
			t.Errorf("warnings = %d, want 0", got)
		}
	})
}
