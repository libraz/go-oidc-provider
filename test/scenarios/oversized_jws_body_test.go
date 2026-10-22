package scenarios_test

import (
	"context"
	"encoding/json"
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
	// The same outline well under the ceiling: it gets past the size
	// gate and is refused for what it is, which tells the two refusals
	// apart.
	smallJWS := "eyJhbGciOiJFUzI1NiJ9.e30.c2ln"

	cases := []struct {
		name string
		path string
		form func(jws string) url.Values
	}{
		{
			// The client assertion is a JWS the OP accepts from an
			// unauthenticated caller by definition — it is how the
			// caller proposes to authenticate.
			name: "token endpoint, client_assertion",
			path: "/oidc/token",
			form: func(jws string) url.Values {
				return url.Values{
					"grant_type":            {"client_credentials"},
					"client_id":             {oversizedClientID},
					"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
					"client_assertion":      {jws},
				}
			},
		},
		{
			// A pushed authorization request carries the request
			// object, the other unauthenticated JWS surface.
			name: "pushed authorization request, request object",
			path: "/oidc/par",
			form: func(jws string) url.Values {
				return url.Values{
					"client_id": {oversizedClientID},
					"request":   {jws},
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tk := testkit.NewProvider(t, testkit.WithOptions(
				op.WithFeature(feature.PAR),
			))
			// The client exists, so an unknown-client refusal cannot
			// stand in for the size gate.
			tk.RegisterClient(t, testkit.ClientFixture{
				ID:         oversizedClientID,
				GrantTypes: []string{"authorization_code", "client_credentials"},
			})

			post := func(jws string) (int, oversizedErrorBody) {
				t.Helper()
				req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
					tk.Server.URL+tc.path, strings.NewReader(tc.form(jws).Encode()))
				if err != nil {
					t.Fatalf("NewRequest: %v", err)
				}
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				resp, err := tk.HTTPClient(nil).Do(req)
				if err != nil {
					t.Fatalf("POST %s: %v", tc.path, err)
				}
				defer resp.Body.Close()
				raw, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatalf("read body: %v", err)
				}
				var eb oversizedErrorBody
				_ = json.Unmarshal(raw, &eb)
				return resp.StatusCode, eb
			}

			// The request must be refused as the client's fault, by the
			// size gate. A 5xx would mean the OP tried and fell over,
			// which is the outcome the bound exists to prevent.
			status, eb := post(oversizedJWS)
			if status != http.StatusBadRequest || eb.Error != "invalid_request" ||
				!strings.Contains(eb.Description, oversizedGateDescription) {
				t.Fatalf("over-cap: status=%d error=%q description=%q; want 400 invalid_request %q",
					status, eb.Error, eb.Description, oversizedGateDescription)
			}

			// Control: under the cap the same request passes the gate,
			// so the refusal above is the length and nothing else.
			status, eb = post(smallJWS)
			if strings.Contains(eb.Description, oversizedGateDescription) {
				t.Fatalf("under-cap: status=%d description=%q; the size gate refused a body under the cap",
					status, eb.Description)
			}
		})
	}
}

const (
	oversizedClientID = "client-oversized"
	// oversizedGateDescription is what /token and /par answer when the
	// bounded body read fails.
	oversizedGateDescription = "malformed form body"
)

type oversizedErrorBody struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
}
