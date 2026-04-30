package registrationendpoint

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"
)

// sectorIdentifierFetchTimeout caps the per-call wall time of the
// outbound fetch. Five seconds is short enough that registration
// latency stays bounded under a slow upstream and long enough that
// network jitter does not cause spurious failures.
const sectorIdentifierFetchTimeout = 5 * time.Second

// sectorIdentifierMaxBodyBytes caps the JSON response body the OP will
// read. Five MiB is far above any realistic redirect_uri list and
// bounds memory use against pathological inputs (gosec G120).
const sectorIdentifierMaxBodyBytes int64 = 5 << 20

// defaultSectorIdentifierClient is the package-default HTTP client the
// fetch uses when [Deps.SectorIdentifierClient] is nil. It is exposed
// as a var so the tests can swap it for a TLS client trusting the
// httptest test root; production code never reassigns it.
//
//nolint:gochecknoglobals // package-default; never mutated outside tests
var defaultSectorIdentifierClient = &http.Client{Timeout: sectorIdentifierFetchTimeout}

// validateSectorIdentifierURI implements the OIDC Core §8.1 fetch
// rule: when sector_identifier_uri is present, the OP MUST GET the
// URL, parse the response as a JSON array of strings, and ensure
// every redirect_uri the client registered is contained in that
// array. Failure at any step yields an invalid_client_metadata error;
// the underlying network / TLS / parse cause goes to the audit log
// only so the response body never leaks upstream information.
func validateSectorIdentifierURI(ctx context.Context, deps Deps, m ClientMetadata) error {
	if m.SectorIdentifierURI == "" {
		return nil
	}
	hc := deps.SectorIdentifierClient
	if hc == nil {
		hc = defaultSectorIdentifierClient
	}
	uris, err := fetchSectorIdentifierDocument(ctx, hc, m.SectorIdentifierURI)
	if err != nil {
		deps.logger().WarnContext(ctx, "dcr.sector_identifier.fetch_failed",
			"sector_identifier_uri", m.SectorIdentifierURI, "err", err)
		return errInvalidClientMetadata("sector_identifier_uri fetch failed")
	}
	for _, redirect := range m.RedirectURIs {
		if !slices.Contains(uris, redirect) {
			deps.logger().WarnContext(ctx, "dcr.sector_identifier.containment_failed",
				"sector_identifier_uri", m.SectorIdentifierURI, "missing", redirect)
			return errInvalidClientMetadata("redirect_uris not contained in sector_identifier_uri document")
		}
	}
	return nil
}

// fetchSectorIdentifierDocument performs the HTTP GET and JSON parse.
// Errors are wrapped with %w so the caller can log the cause without
// surfacing it to the registration response.
func fetchSectorIdentifierDocument(ctx context.Context, hc *http.Client, uri string) ([]string, error) {
	fetchCtx, cancel := context.WithTimeout(ctx, sectorIdentifierFetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, uri, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("http status %d", resp.StatusCode)
	}
	limited := io.LimitReader(resp.Body, sectorIdentifierMaxBodyBytes+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if int64(len(raw)) > sectorIdentifierMaxBodyBytes {
		return nil, errors.New("body exceeds 5 MiB cap")
	}
	var uris []string
	if err := json.Unmarshal(raw, &uris); err != nil {
		return nil, fmt.Errorf("decode body: %w", err)
	}
	return uris, nil
}
