package rs

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/libraz/go-oidc-provider/internal/rpjwks"
	"github.com/libraz/go-oidc-provider/internal/tokens"
)

// serverMetadata is the part of the issuer's discovery document the
// verifier reads.
type serverMetadata struct {
	Issuer                string `json:"issuer"`
	JWKSURI               string `json:"jwks_uri"`
	IntrospectionEndpoint string `json:"introspection_endpoint"`
}

// errMetadata reports a discovery document the verifier cannot use.
var errMetadata = errors.New("rs: unusable discovery document")

// introspect resolves an opaque token through RFC 7662 introspection. An
// inactive answer is invalid_token; a transport or protocol failure is
// the server's own fault and surfaces as 503.
func (v *Verifier) introspect(ctx context.Context, raw string) (*tokens.AccessTokenClaims, map[string]any, *Error) {
	if v.introspection == nil {
		return nil, nil, invalidToken("access token is not a JWT and introspection is not configured")
	}
	endpoint, e := v.introspectionEndpoint(ctx)
	if e != nil {
		return nil, nil, e
	}
	body, err := v.postIntrospection(ctx, endpoint, raw)
	if err != nil {
		v.logFault("introspection request failed", err)
		return nil, nil, unavailable("token introspection is unavailable")
	}
	var all map[string]any
	if err := json.Unmarshal(body, &all); err != nil {
		v.logFault("introspection response is not JSON", err)
		return nil, nil, unavailable("token introspection is unavailable")
	}
	// A missing or null "active" reads as false, as it did when decoded into a bool.
	switch active := all["active"].(type) {
	case nil:
		return nil, nil, invalidToken("access token is not active")
	case bool:
		if !active {
			return nil, nil, invalidToken("access token is not active")
		}
	default:
		v.logFault("introspection response is malformed", errors.New("active is not a boolean"))
		return nil, nil, unavailable("token introspection is unavailable")
	}
	claims, err := tokens.DecodeAccessTokenClaims(body)
	if err != nil {
		v.logFault("introspection response is malformed", err)
		return nil, nil, unavailable("token introspection is unavailable")
	}
	return claims, all, nil
}

// postIntrospection sends the RFC 7662 §2.1 request, authenticated with
// client_secret_basic (RFC 6749 §2.3.1 form-encodes both halves).
func (v *Verifier) postIntrospection(ctx context.Context, endpoint, raw string) ([]byte, error) {
	form := url.Values{"token": {raw}, "token_type_hint": {"access_token"}}
	req, err := v.fetch.NewRequest(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(url.QueryEscape(v.introspection.ClientID), url.QueryEscape(v.introspection.ClientSecret))
	body, _, err := v.fetch.Do(req) //nolint:bodyclose // securefetch.Do drains and closes the body internally.
	return body, err
}

// jwksEndpoint returns the configured JWK Set URL, or the discovered one.
func (v *Verifier) jwksEndpoint(ctx context.Context) (string, *Error) {
	if v.jwksURI != "" {
		return v.jwksURI, nil
	}
	meta, e := v.metadata(ctx)
	if e != nil {
		return "", e
	}
	if meta.JWKSURI == "" {
		return "", unavailable("the issuer publishes no jwks_uri")
	}
	return meta.JWKSURI, nil
}

// introspectionEndpoint returns the configured introspection endpoint, or
// the discovered one.
func (v *Verifier) introspectionEndpoint(ctx context.Context) (string, *Error) {
	if v.introspection.Endpoint != "" {
		return v.introspection.Endpoint, nil
	}
	meta, e := v.metadata(ctx)
	if e != nil {
		return "", e
	}
	if meta.IntrospectionEndpoint == "" {
		return "", unavailable("the issuer publishes no introspection_endpoint")
	}
	return meta.IntrospectionEndpoint, nil
}

// metadata returns the issuer's discovery document, fetching it on first
// use. A success is cached for the verifier's lifetime; a failure is
// remembered for [rpjwks.DefaultNegativeTTL] so a burst of requests during
// an outage costs one outbound fetch, not one per request. The fetch runs
// detached from the caller's cancellation so one disconnecting client
// cannot fail it for everyone waiting.
func (v *Verifier) metadata(ctx context.Context) (*serverMetadata, *Error) {
	v.metaMu.Lock()
	defer v.metaMu.Unlock()
	if v.meta != nil {
		return v.meta, nil
	}
	now := v.clock.Now()
	if !v.metaFailedAt.IsZero() && now.Before(v.metaFailedAt.Add(rpjwks.DefaultNegativeTTL)) {
		return nil, unavailable("the issuer's discovery document is unavailable")
	}
	meta, err := v.discover(context.WithoutCancel(ctx))
	if err != nil {
		v.metaFailedAt = now
		v.logFault("discovery failed", err)
		return nil, unavailable("the issuer's discovery document is unavailable")
	}
	v.meta = meta
	return meta, nil
}

// discover fetches and validates the OpenID Provider metadata (OpenID
// Connect Discovery 1.0 §4). The document must name this issuer exactly,
// and every endpoint it supplies must pass the same URL rule as a
// configured one.
func (v *Verifier) discover(ctx context.Context) (*serverMetadata, error) {
	target := strings.TrimSuffix(v.issuer, "/") + "/.well-known/openid-configuration"
	body, _, err := v.fetch.Get(ctx, target) //nolint:bodyclose // securefetch.Get drains and closes the body internally.
	if err != nil {
		return nil, err
	}
	var meta serverMetadata
	if err := json.Unmarshal(body, &meta); err != nil {
		return nil, errors.Join(errMetadata, err)
	}
	if meta.Issuer != v.issuer {
		return nil, errors.Join(errMetadata, errors.New("issuer does not match Config.Issuer"))
	}
	for _, ep := range [...]struct{ name, raw string }{
		{"jwks_uri", meta.JWKSURI},
		{"introspection_endpoint", meta.IntrospectionEndpoint},
	} {
		if ep.raw == "" {
			continue
		}
		if err := v.rule.check(ep.name, ep.raw); err != nil {
			return nil, errors.Join(errMetadata, err)
		}
	}
	return &meta, nil
}
