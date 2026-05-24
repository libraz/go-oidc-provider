// Package protectedresource builds and serves OAuth 2.0 Protected
// Resource Metadata documents (RFC 9728). The OP hosts one
// /.well-known/oauth-protected-resource document per resource server an
// embedder registers; the OP itself does not validate bearer tokens —
// that remains the resource server's job. This package owns the JSON
// document shape, the RFC 9728 §3.1 path derivation, and the read-only
// HTTP handler.
package protectedresource

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

// WellKnownPrefix is the fixed path segment RFC 9728 §3 reserves for
// protected-resource metadata. A resource whose identifier carries a
// path component appends that component per §3.1 (see [WellKnownPath]).
const WellKnownPrefix = "/.well-known/oauth-protected-resource"

// CacheControl mirrors the discovery document's caching posture: a
// one-hour cache with a ten-minute stale-while-revalidate window. The
// metadata is configuration-static for the lifetime of the process, so
// a long max-age is safe.
const CacheControl = "public, max-age=3600, stale-while-revalidate=600"

// Document is the RFC 9728 §2 metadata object. Every field except
// resource is optional and omitted when empty so the served JSON carries
// only the parameters the embedder populated.
type Document struct {
	Resource                          string   `json:"resource"`
	AuthorizationServers              []string `json:"authorization_servers,omitempty"`
	JWKSURI                           string   `json:"jwks_uri,omitempty"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
	BearerMethodsSupported            []string `json:"bearer_methods_supported,omitempty"`
	ResourceSigningAlgValuesSupported []string `json:"resource_signing_alg_values_supported,omitempty"`
	ResourceDocumentation             string   `json:"resource_documentation,omitempty"`
}

// Input is the builder's source: one registered resource server plus the
// OP's own issuer, which RFC 9728 §3.3 expects to appear in
// authorization_servers.
type Input struct {
	Resource                          string
	Issuer                            string
	ScopesSupported                   []string
	BearerMethodsSupported            []string
	ResourceSigningAlgValuesSupported []string
	JWKSURI                           string
	ResourceDocumentation             string
}

// Build assembles the metadata Document. authorization_servers is always
// the single-element list naming the OP issuer; the slices are defensively
// copied so a later mutation of the caller's input cannot reach the
// document the handler marshals.
func Build(in Input) Document {
	return Document{
		Resource:                          in.Resource,
		AuthorizationServers:              []string{in.Issuer},
		JWKSURI:                           in.JWKSURI,
		ScopesSupported:                   cloneNonEmpty(in.ScopesSupported),
		BearerMethodsSupported:            cloneNonEmpty(in.BearerMethodsSupported),
		ResourceSigningAlgValuesSupported: cloneNonEmpty(in.ResourceSigningAlgValuesSupported),
		ResourceDocumentation:             in.ResourceDocumentation,
	}
}

// WellKnownPath returns the request path at which the document for
// resource MUST be served, following RFC 9728 §3.1: the fixed
// /.well-known/oauth-protected-resource prefix, with the resource
// identifier's path component (if any) appended. A resource with no path
// (or a bare "/") is served at the prefix itself.
//
// resource is assumed already validated as an absolute URI (the option
// layer canonicalises it); a parse failure falls back to the bare prefix
// so the caller never produces a malformed mount pattern.
func WellKnownPath(resource string) string {
	u, err := url.Parse(resource)
	if err != nil {
		return WellKnownPrefix
	}
	p := strings.TrimRight(u.Path, "/")
	if p == "" {
		return WellKnownPrefix
	}
	return WellKnownPrefix + p
}

// Handler returns a read-only [http.Handler] that serves doc as JSON.
// The body is marshalled once and reused; the handler answers GET and
// HEAD only and stamps the shared cache-control header, mirroring the
// discovery handler's contract.
func Handler(doc Document) (http.Handler, error) {
	body, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", CacheControl)
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write(body)
	}), nil
}

// cloneNonEmpty returns a defensive copy of in, or nil when in is empty
// so the json:omitempty tag drops the field entirely.
func cloneNonEmpty(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	return append([]string(nil), in...)
}
