package clientencjwks

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/netsec"
)

// fetcher performs the JWKS HTTP round-trip with the SSRF deny-list,
// the body cap, and the status / parse checks the resolver requires.
//
// The struct is intentionally a thin wrapper around an [*http.Client]
// constructed via [netsec.NewHTTPClient]: the client carries a
// dial-time hook that re-checks every resolved address against the
// deny-list so a DNS-rebinding attacker cannot widen the surface
// between the URL-time gate and the actual TCP dial. The matching
// URL-time gate runs in [fetcher.fetch] before the request is built.
type fetcher struct {
	client       *http.Client
	maxBodyBytes int64
	allowPrivate bool
}

// netsecOptions returns the [netsec.Options] snapshot the fetcher
// uses for the URL-time gate so it stays in lockstep with the
// dial-time gate baked into f.client.
func (f *fetcher) netsecOptions() netsec.Options {
	return netsec.Options{
		AllowPrivate: f.allowPrivate,
	}
}

// fetch retrieves the JWKS document at url. The function applies the
// SSRF deny-list, the per-request timeout (carried on the underlying
// [*http.Client]), the body cap, the 2xx status check, and the JSON
// parse before returning the parsed keyset.
//
// Every failure mode wraps [ErrJWKSFetch] so the caller branches on
// the sentinel via [errors.Is] without inspecting the wrapped cause.
func (f *fetcher) fetch(ctx context.Context, url string) (*josev4.JSONWebKeySet, error) {
	if err := netsec.AssertSafeURL(ctx, url, f.netsecOptions()); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrJWKSFetch, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrJWKSFetch, err)
	}
	req.Header.Set("Accept", "application/json")

	// The URL came from preregistered client metadata that already
	// passed the SSRF deny-list above, so the variable URL is not
	// an attacker-controlled redirect into the OP's own network.
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrJWKSFetch, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("%w: status %d", ErrJWKSFetch, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, f.maxBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: read body: %w", ErrJWKSFetch, err)
	}
	if int64(len(body)) > f.maxBodyBytes {
		return nil, fmt.Errorf("%w: body exceeds %d bytes", ErrJWKSFetch, f.maxBodyBytes)
	}
	return parseJWKS(body)
}

// newSSRFClient returns an [*http.Client] whose transport carries
// the dial-time SSRF deny-list. The function lives in this file (not
// resolver.go) so the wiring sits next to the only caller that
// needs the bare un-timed client.
func newSSRFClient(allowPrivate bool, base http.RoundTripper) *http.Client {
	return netsec.NewHTTPClient(netsec.Options{
		AllowPrivate:  allowPrivate,
		BaseTransport: base,
	})
}

// parseJWKS decodes body into a [*josev4.JSONWebKeySet]. An empty
// body or a JSON-decode failure surfaces as [ErrJWKSFetch]; an empty
// keys array is tolerated at this layer because the resolver's key
// selection step surfaces [ErrNoMatchingKey] when no key matches.
func parseJWKS(body []byte) (*josev4.JSONWebKeySet, error) {
	if len(body) == 0 {
		return nil, fmt.Errorf("%w: empty body", ErrJWKSFetch)
	}
	var keys josev4.JSONWebKeySet
	if err := json.Unmarshal(body, &keys); err != nil {
		return nil, fmt.Errorf("%w: parse jwks: %w", ErrJWKSFetch, err)
	}
	return &keys, nil
}
