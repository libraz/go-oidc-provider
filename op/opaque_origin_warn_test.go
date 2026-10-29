package op_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/op"
)

// postOpaqueOriginLogout sends a confirmation POST that carries
// Origin: null from a same-origin form and returns the status.
func postOpaqueOriginLogout(tb testing.TB, provider *op.Provider) int {
	tb.Helper()
	form := url.Values{"logout_csrf": {"x"}, "logout_scope_fingerprint": {"all"}}
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost,
		validIssuer+endSessionCeremonyPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "null")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.AddCookie(&http.Cookie{Name: logoutConfirmCookie, Value: "x"})
	resp := serveCeremony(tb, provider, req)
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func TestOpaqueOriginWarn_OncePerProvider(t *testing.T) {
	t.Parallel()

	const marker = "Origin: null on a same-origin form POST"
	build := func(sink *syncBuffer) *op.Provider {
		t.Helper()
		logger := slog.New(slog.NewTextHandler(sink, &slog.HandlerOptions{Level: slog.LevelWarn}))
		p, err := op.New(append(validBaseOpts(t), op.WithLogger(logger))...)
		if err != nil {
			t.Fatalf("op.New: %v", err)
		}
		return p
	}

	var sinkA, sinkB syncBuffer
	a, b := build(&sinkA), build(&sinkB)

	for range 3 {
		if got := postOpaqueOriginLogout(t, a); got != http.StatusBadRequest {
			t.Fatalf("status=%d want 400", got)
		}
	}
	if n := strings.Count(sinkA.String(), marker); n != 1 {
		t.Errorf("provider A logged the warning %d times, want 1; log=%s", n, sinkA.String())
	}
	if strings.Contains(sinkB.String(), marker) {
		t.Error("provider B logged a warning for provider A's traffic")
	}

	if got := postOpaqueOriginLogout(t, b); got != http.StatusBadRequest {
		t.Fatalf("status=%d want 400", got)
	}
	if n := strings.Count(sinkB.String(), marker); n != 1 {
		t.Errorf("provider B logged the warning %d times, want 1", n)
	}
}
