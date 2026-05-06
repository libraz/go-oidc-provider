package clientencjwks

import (
	"context"
	"encoding/json"
	"fmt"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/securefetch"
)

// fetcher performs the JWKS HTTP round-trip with the SSRF deny-list,
// the body cap, and the status / parse checks the resolver requires.
//
// The struct is intentionally a thin wrapper around a
// [*securefetch.Client]: that client carries the URL-time and dial-time
// SSRF gate, the per-request timeout, and the body cap. The fetcher
// only adds the JWKS-specific JSON parse on top of the shared
// envelope.
type fetcher struct {
	client *securefetch.Client
}

// fetch retrieves the JWKS document at url. The function applies the
// SSRF deny-list, the per-request timeout, the body cap, the 2xx
// status check, and the JSON parse before returning the parsed keyset.
//
// Every failure mode wraps [ErrJWKSFetch] so the caller branches on
// the sentinel via [errors.Is] without inspecting the wrapped cause.
func (f *fetcher) fetch(ctx context.Context, url string) (*josev4.JSONWebKeySet, error) {
	body, _, err := f.client.Get(ctx, url) //nolint:bodyclose // securefetch.Get drains and closes the body internally.
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrJWKSFetch, err)
	}
	return parseJWKS(body)
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
