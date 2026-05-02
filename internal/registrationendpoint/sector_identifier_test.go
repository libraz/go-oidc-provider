// Test file exercises the sector_identifier_uri validator wrapper that
// adapts [sector.Resolver] to the RFC 7591 invalid_client_metadata
// envelope. The resolver-internal contract (SSRF deny-list, redirect
// refusal, body cap, cache poisoning detection) is covered exhaustively
// in internal/sector/resolver_test.go; tests here pin the wire shape
// and the error-mapping table the registration handler depends on.
//
//nolint:testpackage // exercises unexported helpers
package registrationendpoint

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/sector"
)

// newTLSSectorServer returns an httptest TLS server serving body with
// the supplied status. The server's certificate is the test root the
// returned client trusts; production paths use the system pool.
func newTLSSectorServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// newSectorTestResolver builds a resolver wired to trust the
// httptest server's self-signed cert and to admit the loopback
// address the server listens on. Production code never uses this
// combination; it is the test-only escape hatch the resolver
// package's [sector.AllowPrivateNetwork] and [sector.WithHTTPClient]
// options exist to support.
func newSectorTestResolver(srv *httptest.Server) *sector.Resolver {
	return sector.New(
		sector.WithHTTPClient(srv.Client()),
		sector.AllowPrivateNetwork(),
	)
}

func TestValidateSectorIdentifierURI_Empty(t *testing.T) {
	t.Parallel()

	if err := validateSectorIdentifierURI(context.Background(), Deps{}, ClientMetadata{}); err != nil {
		t.Fatalf("empty sector_identifier_uri must not error: %v", err)
	}
}

func TestValidateSectorIdentifierURI_FetchAndContainment(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		body        string
		status      int
		redirects   []string
		wantErrText string
	}{
		{
			name:      "contains all redirects",
			body:      `["https://rp.example.com/cb1","https://rp.example.com/cb2"]`,
			status:    http.StatusOK,
			redirects: []string{"https://rp.example.com/cb1"},
		},
		{
			name:        "missing redirect",
			body:        `["https://rp.example.com/cb1"]`,
			status:      http.StatusOK,
			redirects:   []string{"https://rp.example.com/cb1", "https://rp.example.com/cb2"},
			wantErrText: "not contained",
		},
		{
			name:        "non-2xx status",
			body:        `["https://rp.example.com/cb1"]`,
			status:      http.StatusNotFound,
			redirects:   []string{"https://rp.example.com/cb1"},
			wantErrText: "fetch failed",
		},
		{
			name:        "invalid JSON",
			body:        `not json`,
			status:      http.StatusOK,
			redirects:   []string{"https://rp.example.com/cb1"},
			wantErrText: "malformed",
		},
		{
			name:        "JSON object instead of array",
			body:        `{"uris":["https://rp.example.com/cb1"]}`,
			status:      http.StatusOK,
			redirects:   []string{"https://rp.example.com/cb1"},
			wantErrText: "malformed",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := newTLSSectorServer(t, tc.status, tc.body)
			deps := Deps{SectorResolver: newSectorTestResolver(srv)}
			meta := ClientMetadata{
				RedirectURIs:        tc.redirects,
				SectorIdentifierURI: srv.URL,
			}
			err := validateSectorIdentifierURI(context.Background(), deps, meta)
			if tc.wantErrText == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErrText)
			}
			var ve *validationError
			if !errors.As(err, &ve) || ve.code != codeInvalidClientMetadata {
				t.Fatalf("expected invalid_client_metadata error, got %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantErrText) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErrText)
			}
		})
	}
}

// TestValidateSectorIdentifierURI_NetworkError covers the case where
// the upstream is unreachable: the server is started and immediately
// closed so the resolver's underlying transport returns a
// connection-refused error. The wrapper must surface
// invalid_client_metadata with the generic "fetch failed" description
// (specific transport details stay in the operator log).
func TestValidateSectorIdentifierURI_NetworkError(t *testing.T) {
	t.Parallel()

	srv := newTLSSectorServer(t, http.StatusOK, `["https://rp.example.com/cb"]`)
	url := srv.URL
	srv.Close()

	deps := Deps{SectorResolver: newSectorTestResolver(srv)}
	meta := ClientMetadata{
		RedirectURIs:        []string{"https://rp.example.com/cb"},
		SectorIdentifierURI: url,
	}
	err := validateSectorIdentifierURI(context.Background(), deps, meta)
	if err == nil {
		t.Fatalf("expected error when upstream is unreachable")
	}
	if !strings.Contains(err.Error(), "fetch failed") {
		t.Fatalf("error %q should mention fetch failure", err.Error())
	}
}

// TestValidateSectorIdentifierURI_PrivateNetworkRejected confirms
// that with the default (production) resolver — no
// AllowPrivateNetwork opt-in — a sector_identifier_uri pointing at a
// loopback test server is rejected with the specific private-address
// description. The check guards against an embedder accidentally
// disabling the SSRF gate by omitting the resolver.
func TestValidateSectorIdentifierURI_PrivateNetworkRejected(t *testing.T) {
	t.Parallel()

	srv := newTLSSectorServer(t, http.StatusOK, `["https://rp.example.com/cb"]`)
	// Production-shape resolver: trust the httptest cert so transport
	// reaches the gate, but do NOT opt into private networks. The URI
	// must be rejected at the SSRF check, not the TLS handshake.
	resolver := sector.New(sector.WithHTTPClient(srv.Client()))
	deps := Deps{SectorResolver: resolver}
	meta := ClientMetadata{
		RedirectURIs:        []string{"https://rp.example.com/cb"},
		SectorIdentifierURI: srv.URL,
	}
	err := validateSectorIdentifierURI(context.Background(), deps, meta)
	if err == nil {
		t.Fatalf("expected private-address rejection")
	}
	if !strings.Contains(err.Error(), "private address") {
		t.Fatalf("error %q does not mention private address", err.Error())
	}
}

// TestValidateSectorIdentifierURI_NilResolverFallsBackToDefault
// pins the wrapper's safety contract: a unit test that omits
// Deps.SectorResolver still goes through the production posture (no
// AllowPrivateNetwork, https-only). The test confirms the fallback
// resolver rejects an http URL — the same posture the production
// op layer constructs.
func TestValidateSectorIdentifierURI_NilResolverFallsBackToDefault(t *testing.T) {
	t.Parallel()

	meta := ClientMetadata{
		RedirectURIs:        []string{"https://rp.example.com/cb"},
		SectorIdentifierURI: "http://rp.example.com/sector.json",
	}
	err := validateSectorIdentifierURI(context.Background(), Deps{}, meta)
	if err == nil {
		t.Fatalf("expected rejection of http scheme")
	}
	var ve *validationError
	if !errors.As(err, &ve) || ve.code != codeInvalidClientMetadata {
		t.Fatalf("expected invalid_client_metadata, got %v", err)
	}
}
