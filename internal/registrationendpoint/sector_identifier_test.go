// Test file exercises the sector_identifier_uri fetch validator in
// isolation: the validator is called downstream of the structural
// https / absolute / fragment-free check, so the unit tests pass plain
// http URLs from httptest servers without needing to thread a TLS
// trust pool through the fixture.
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
)

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
			wantErrText: "redirect_uris not contained",
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
			wantErrText: "fetch failed",
		},
		{
			name:        "JSON object instead of array",
			body:        `{"uris":["https://rp.example.com/cb1"]}`,
			status:      http.StatusOK,
			redirects:   []string{"https://rp.example.com/cb1"},
			wantErrText: "fetch failed",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			t.Cleanup(srv.Close)

			deps := Deps{SectorIdentifierClient: srv.Client()}
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

// TestValidateSectorIdentifierURI_BodyCap confirms the 5 MiB cap fires
// before the JSON parser sees the body. The handler streams the body
// through a LimitReader sized one byte over the cap so an oversize
// response is detectable without buffering an unbounded payload.
func TestValidateSectorIdentifierURI_BodyCap(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Open a JSON array but never close it — the server keeps writing
		// until the LimitReader cap closes the connection.
		_, _ = w.Write([]byte(`["`))
		filler := strings.Repeat("A", 1024)
		for written := 0; written < int(sectorIdentifierMaxBodyBytes)+2048; written += len(filler) {
			if _, err := w.Write([]byte(filler)); err != nil {
				return
			}
		}
	}))
	t.Cleanup(srv.Close)

	deps := Deps{SectorIdentifierClient: srv.Client()}
	meta := ClientMetadata{
		RedirectURIs:        []string{"https://rp.example.com/cb"},
		SectorIdentifierURI: srv.URL,
	}
	err := validateSectorIdentifierURI(context.Background(), deps, meta)
	if err == nil {
		t.Fatalf("expected error on oversized body")
	}
	var ve *validationError
	if !errors.As(err, &ve) || ve.code != codeInvalidClientMetadata {
		t.Fatalf("expected invalid_client_metadata, got %v", err)
	}
}

// TestValidateSectorIdentifierURI_NetworkError covers the case where
// the upstream is unreachable: the server is started and immediately
// closed so Do() returns a connection-refused error. The validator
// must surface invalid_client_metadata with a stable message.
func TestValidateSectorIdentifierURI_NetworkError(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()

	deps := Deps{SectorIdentifierClient: &http.Client{Timeout: sectorIdentifierFetchTimeout}}
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
