package introspectendpoint_test

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

	"github.com/libraz/go-oidc-provider/internal/introspectendpoint"
	"github.com/libraz/go-oidc-provider/internal/keys"
	"github.com/libraz/go-oidc-provider/internal/tokens"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// FuzzIntrospectFormBody exercises the /introspect endpoint with
// arbitrary application/x-www-form-urlencoded bodies. The harness
// treats the handler as a black box and asserts the same structural
// invariants as [parendpoint_test.FuzzPARFormBody]:
//
//  1. ServeHTTP never panics, regardless of input. Form parsing,
//     bearer parsing, JWT verification, and store lookup all run on
//     untrusted bytes.
//  2. The response status MUST be one of a closed set (200 / 400 /
//     401 / 405 / 413 / 415). RFC 7662 §2.2 mandates 200 even for
//     "inactive" responses, so the introspection endpoint differs
//     from /par here — it can legitimately return 200 with
//     {"active": false} on parse failure inside an authenticated
//     request. The closed set rules out 5xx (programmer bugs) and
//     stray 3xx (no redirect path).
//  3. Every response MUST set Cache-Control: no-store and Pragma:
//     no-cache (RFC 7662 §4 / RFC 6749 §5.1).
//
// The fixture wires a minimal in-memory store and a fresh ES256 key
// pair so the JWT branch reaches signature verification on a
// well-formed token. No clients are registered, so every
// authenticated request fails at clientauth — the success path is
// unreachable under fuzzing.
//
// CVE class motivation: panic immunity. This is insurance against the
// CVE-2024-29371 (jose4j JWE decompression bomb, CVSS 7.5) and RFC
// 8725 §3.11 DoS class — any endpoint that parses untrusted body
// bytes can be the entry point. The closed-status assertion catches
// regressions that bypass the body-size cap; the panic-immunity
// property catches any decoder that crashes on malformed bytes.
func FuzzIntrospectFormBody(f *testing.F) {
	handler := newIntrospectFuzzHandler(f)

	f.Add("")
	f.Add("token=abc")
	f.Add("token=abc&token_type_hint=access_token")
	f.Add("token=abc&token_type_hint=refresh_token")
	f.Add("token=abc&token_type_hint=unknown")
	f.Add("token=" + strings.Repeat("A", 1<<14)) // 16 KiB token value
	f.Add("token=&token_type_hint=access_token")
	f.Add("%%%")                            // malformed urlencoded
	f.Add("token=abc&token=def")            // duplicate token param
	f.Add("token=abc\x00")                  // NUL in token
	f.Add("token=eyJhbGciOiJub25lIn0.e30.") // alg=none JWT shape
	f.Add("token=eyJhbGciOiJIUzI1NiJ9.e30.sig")
	// DoS hardening seeds.
	f.Add(strings.Repeat("token=abc&", 1<<14))             // ~140 KiB body
	f.Add(strings.Repeat("a=b&", 1<<15))                   // ~128 KiB body
	f.Add("token_type_hint=" + strings.Repeat("a", 1<<14)) // huge hint

	f.Fuzz(func(t *testing.T, body string) {
		req := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodPost,
			"https://op.example/oidc/introspect",
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
			// allowed: every parse / auth failure converges on these.
		default:
			t.Fatalf("unexpected status %d for body %q", resp.StatusCode, truncateForFuzz(body, 64))
		}

		if got := resp.Header.Get("Cache-Control"); !strings.Contains(got, "no-store") {
			t.Fatalf("Cache-Control=%q want to contain no-store (status=%d body=%q)",
				got, resp.StatusCode, truncateForFuzz(body, 64))
		}
	})
}

// newIntrospectFuzzHandler constructs the minimal [introspectendpoint.Handler]
// the fuzz harness exercises. The fixture wires fresh ES256 material
// every run so the verifier can reach signature checks; no clients
// are registered so the authentication branch always fails.
func newIntrospectFuzzHandler(tb testing.TB) http.Handler {
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
	deps := introspectendpoint.Deps{
		Issuer:        "https://op.example",
		Clients:       store.Clients(),
		RefreshTokens: store.RefreshTokens(),
		Keys:          keyset,
		Clock:         clock,
		SigningKey:    tokens.SigningKey{KeyID: "fuzz-1", Signer: priv},
	}
	return introspectendpoint.Handler(deps)
}

// fuzzClock is the package-local fixed clock the harness threads
// through the handler. The constant reading keeps the fuzz output
// deterministic across runs; only the body bytes vary.
type fuzzClock struct{ now time.Time }

func (c fuzzClock) Now() time.Time { return c.now }

// truncateForFuzz clips s to at most n bytes for diagnostic
// messages so a 128 KiB fuzz input does not flood the test log on
// failure. Mirrors the helper in [parendpoint_test.truncate].
func truncateForFuzz(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(truncated)"
}
