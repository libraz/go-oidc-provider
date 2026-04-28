package parendpoint_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/parendpoint"
	"github.com/libraz/go-oidc-provider/op/storeadapter/inmem"
)

// FuzzPARFormBody exercises the PAR endpoint with arbitrary
// application/x-www-form-urlencoded bodies. The harness treats the
// handler as a black box and asserts three structural invariants:
//
//  1. ServeHTTP never panics, regardless of input. Form parsing,
//     authentication parsing, and authorize-request parsing all run on
//     untrusted bytes; a single panic here would crash the OP process.
//  2. The response status MUST be one of a closed set of HTTP codes
//     (400 / 401 / 405 / 413 / 500). RFC 9126 §2.3 plus this library's
//     /par contract admit no other code from the parse path; a 200 / 201
//     would mean the fuzzer accidentally produced a fully valid request,
//     which the seed corpus does NOT contain (no client is registered),
//     so a 2xx success is a contract violation.
//  3. Every response MUST set Cache-Control: no-store and Pragma: no-cache,
//     because RFC 6749 §5.1 mandates them on every PAR response. Drift
//     here is the most common silent regression, so the fuzzer pins it.
//
// The harness uses a single fixed Deps with an empty in-memory store —
// no clients are registered, so every authenticated request is rejected
// with invalid_client. That keeps the success path unreachable under
// fuzzing and isolates the test to byte-parsing behaviour.
//
// Seed rationale:
//   - empty body: ParseForm succeeds with no values; auth fails.
//   - minimal valid form (response_type=code only): runs through every
//     parser layer before being rejected at authentication.
//   - duplicate client_id: RFC 6749 §3.1 single-value rule.
//   - "%%%": malformed urlencoded body; ParseForm error → 400.
//   - field with embedded NUL: parser tolerance check.
//   - 65 KiB body: hits the maxFormBytes ceiling; expect 413 / 400.
//   - body declaring request_uri (forbidden in PAR): 400.
//   - body with bare "client_assertion=...": triggers the
//     private_key_jwt unsupported path; 401 invalid_client.
func FuzzPARFormBody(f *testing.F) {
	clock := fixedClock{now: time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)}
	store := inmem.New(inmem.WithClock(clock))
	deps := parendpoint.Deps{
		Issuer:  "https://op.example",
		Clients: store.Clients(),
		PARs:    store.PushedAuthRequests(),
		Clock:   clock,
	}
	handler := parendpoint.Handler(deps)

	// 65 KiB of "a=b&" runs to trip the 64 KiB MaxBytesReader.
	big := strings.Repeat("a=b&", 17000)

	f.Add("")
	f.Add("response_type=code")
	f.Add("client_id=alice&client_id=bob")
	f.Add("%%%")
	f.Add("response_type=code&state=\x00")
	f.Add(big)
	f.Add("request_uri=urn:ietf:params:oauth:request_uri:abc")
	f.Add("client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&client_assertion=eyJhbGciOiJFUzI1NiJ9.e30.sig")
	// DoS hardening seeds. CVE-2024-29371 (CVSS 7.5; jose4j JWE
	// decompression bomb) and RFC 8725 §3.11 motivate stress-testing
	// the body-size ceiling. MaxBytesReader should reject oversize
	// bodies as 413 before any CPU-bound parsing kicks in; a
	// regression bypassing the cap surfaces via the closed-status
	// assertion below.
	f.Add(strings.Repeat("a=b&", 1<<14))                       // ~64 KiB exact.
	f.Add(strings.Repeat("a=b&", 1<<15))                       // ~128 KiB: must 413.
	f.Add(strings.Repeat("scope=openid+profile+email&", 5000)) // repeated valid-looking pairs.
	f.Add("client_id=" + strings.Repeat("A", 1<<14))           // single huge value.
	f.Add("scope=" + strings.Repeat("openid+", 8000))          // huge space-separated list.

	f.Fuzz(func(t *testing.T, body string) {
		req := httptest.NewRequestWithContext(
			context.Background(),
			http.MethodPost,
			"https://op.example/oidc/par",
			strings.NewReader(body),
		)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		resp := rec.Result()
		defer resp.Body.Close()

		switch resp.StatusCode {
		case http.StatusBadRequest,
			http.StatusUnauthorized,
			http.StatusMethodNotAllowed,
			http.StatusRequestEntityTooLarge,
			http.StatusInternalServerError:
			// allowed: every parse / auth failure converges on these.
		default:
			t.Fatalf("unexpected status %d for body %q", resp.StatusCode, truncate(body, 64))
		}

		if got := resp.Header.Get("Cache-Control"); got != "no-store" {
			t.Fatalf("Cache-Control=%q want no-store (status=%d body=%q)",
				got, resp.StatusCode, truncate(body, 64))
		}
		if got := resp.Header.Get("Pragma"); got != "no-cache" {
			t.Fatalf("Pragma=%q want no-cache (status=%d body=%q)",
				got, resp.StatusCode, truncate(body, 64))
		}
	})
}

// truncate clips s to at most n bytes for diagnostic messages so a 64 KiB
// fuzz input does not flood the test log on failure.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...(truncated)"
}
