package scenarios_test

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/httpx"
	"github.com/libraz/go-oidc-provider/op"
	"github.com/libraz/go-oidc-provider/op/feature"
	"github.com/libraz/go-oidc-provider/op/testkit"
)

// TestEndpoints_OversizedJWSIsRefusedBeforeItIsDecoded pins that the
// size of a client-supplied JWS is decided before any of it is parsed.
//
// A compact JWS is three base64url segments, and decoding one costs
// memory proportional to its length. That is fine when the length is
// bounded and a problem when it is not: an unauthenticated caller who
// can name the size of a segment can name the OP's allocation, and the
// segments that are cheapest to inflate are the ones verification would
// have thrown away anyway. Refusing on length first is what keeps the
// cost of a hostile request proportional to the request rather than to
// what it claims to contain — and it has to happen at the read, since
// by the time a parser has something to reject, the allocation already
// happened.
//
// The bound is the OP's own rather than the transport's. A deployment
// behind a proxy that caps bodies is a deployment that happens to be
// safe today; the library cannot assume one is there.
//
// Tracks: CVE-2026-48525 (PyJWT) — the payload segment was
// base64url-decoded before the code decided it was not needed, giving
// an unauthenticated caller a denial-of-service primitive. Alias class:
// CVE-2025-61920 (Authlib, oversized JOSE segments).
func TestEndpoints_OversizedJWSIsRefusedBeforeItIsDecoded(t *testing.T) {
	t.Parallel()

	// A JWS-shaped value whose middle segment alone is past the body
	// ceiling. It is deliberately well-formed in outline — three
	// dot-separated base64url runs — so nothing rejects it on shape
	// before the size gate has had its say.
	oversizedSegment := strings.Repeat("A", httpx.MaxFormBytes+1)
	oversizedJWS := "eyJhbGciOiJFUzI1NiJ9." + oversizedSegment + ".c2ln"

	cases := []struct {
		name string
		path string
		form url.Values
	}{
		{
			// The client assertion is a JWS the OP accepts from an
			// unauthenticated caller by definition — it is how the
			// caller proposes to authenticate.
			name: "token endpoint, client_assertion",
			path: "/oidc/token",
			form: url.Values{
				"grant_type":            {"client_credentials"},
				"client_id":             {"client-oversized"},
				"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
				"client_assertion":      {oversizedJWS},
			},
		},
		{
			// A pushed authorization request carries the request
			// object, the other unauthenticated JWS surface.
			name: "pushed authorization request, request object",
			path: "/oidc/par",
			form: url.Values{
				"client_id": {"client-oversized"},
				"request":   {oversizedJWS},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tk := testkit.NewProvider(t, testkit.WithOptions(
				op.WithFeature(feature.PAR),
			))
			body := tc.form.Encode()
			req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
				tk.Server.URL+tc.path, strings.NewReader(body))
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

			resp, err := tk.HTTPClient(nil).Do(req)
			if err != nil {
				t.Fatalf("POST %s: %v", tc.path, err)
			}
			defer resp.Body.Close()
			if _, err := io.Copy(io.Discard, resp.Body); err != nil {
				t.Fatalf("drain body: %v", err)
			}

			// The request must be refused as the client's fault. A 5xx
			// would mean the OP tried and fell over, which is the
			// outcome the bound exists to prevent.
			if resp.StatusCode < 400 || resp.StatusCode >= 500 {
				t.Fatalf("status=%d; an over-cap body must be refused as a client error, not accepted or crashed",
					resp.StatusCode)
			}
		})
	}
}
