package revokeendpoint_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/revokeendpoint"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// FuzzRevokeFormBody exercises the /revoke endpoint with arbitrary
// application/x-www-form-urlencoded bodies. Mirrors the introspect
// and PAR fuzz harnesses; the structural invariants are:
//
//  1. ServeHTTP never panics, regardless of input.
//  2. Status MUST be one of a closed set: 200 / 400 / 401 / 405 /
//     413 / 415. RFC 7009 §2.2 says the OP MUST respond 200 even
//     when the token is unknown — disclosure-equivalence — so 200
//     is the most common path under fuzzing. 5xx (programmer bugs)
//     and 3xx (no redirect path here) MUST never appear.
//  3. Cache-Control: no-store is mandated by RFC 6749 §5.1 on every
//     response.
//
// The fixture wires a minimal in-memory store + ES256 keyset; no
// clients are registered, so authentication fails on every request,
// keeping the fuzz isolated to byte-parsing behaviour.
//
// CVE class motivation: panic immunity. RFC 8725 §3.11 / CVE-2024-29371
// motivate stress-testing the body-size cap; the closed-status
// assertion catches a regression that bypasses MaxBytesReader.
func FuzzRevokeFormBody(f *testing.F) {
	handler := newRevokeFuzzHandler(f)

	f.Add("")
	f.Add("token=abc")
	f.Add("token=abc&token_type_hint=access_token")
	f.Add("token=abc&token_type_hint=refresh_token")
	f.Add("token=abc&token_type_hint=unknown")
	f.Add("token=" + strings.Repeat("X", 1<<14))
	f.Add("token=&token_type_hint=refresh_token")
	f.Add("%%%")
	f.Add("token=abc&token=def")
	f.Add("token=abc\x00")
	f.Add("token=eyJhbGciOiJub25lIn0.e30.")
	f.Add("token=eyJhbGciOiJIUzI1NiJ9.e30.sig")
	// DoS hardening seeds.
	f.Add(strings.Repeat("token=abc&", 1<<14))
	f.Add(strings.Repeat("a=b&", 1<<15))
	f.Add("token_type_hint=" + strings.Repeat("a", 1<<14))

	f.Fuzz(func(t *testing.T, body string) {
		req := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodPost,
			"https://op.example/oidc/revoke",
			strings.NewReader(body),
		)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		resp := rec.Result()
		defer resp.Body.Close()

		switch resp.StatusCode {
		case http.StatusOK,
			http.StatusBadRequest,
			http.StatusUnauthorized,
			http.StatusMethodNotAllowed,
			http.StatusUnsupportedMediaType,
			http.StatusRequestEntityTooLarge:
			// allowed.
		default:
			t.Fatalf("unexpected status %d for body %q", resp.StatusCode, truncateForFuzz(body, 64))
		}

		if got := resp.Header.Get("Cache-Control"); !strings.Contains(got, "no-store") {
			t.Fatalf("Cache-Control=%q want to contain no-store (status=%d body=%q)",
				got, resp.StatusCode, truncateForFuzz(body, 64))
		}
	})
}

// newRevokeFuzzHandler is the [introspect_fuzz_test.go] equivalent
// for /revoke: minimal Deps, fresh ES256 keyset, empty client store,
// fixed clock.
func newRevokeFuzzHandler(tb testing.TB) http.Handler {
	tb.Helper()
	clock := fuzzClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		tb.Fatalf("ecdsa key: %v", err)
	}
	keyset, err := keys.NewSet([]keys.Entry{{KeyID: "fuzz-1", Signer: priv}})
	if err != nil {
		tb.Fatalf("keys.NewSet: %v", err)
	}
	store := inmem.New(inmem.WithClock(clock))
	deps := revokeendpoint.Deps{
		Issuer:        "https://op.example",
		Clients:       store.Clients(),
		RefreshTokens: store.RefreshTokens(),
		Keys:          keyset,
		Clock:         clock,
	}
	return revokeendpoint.Handler(deps)
}

type fuzzClock struct{ now time.Time }

func (c fuzzClock) Now() time.Time { return c.now }

func truncateForFuzz(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(truncated)"
}
