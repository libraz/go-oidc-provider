package rpjwks

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/jose"
	"github.com/libraz/go-oidc-provider/internal/securefetch"
)

// ParseKeySet decodes a JWK Set document with the package-wide member cap
// applied. Callers that hold a keyset inline on the client record share it with
// the fetched path so both are bounded and both tolerate members this build
// cannot represent.
//
// Errors are returned bare so the calling package can wrap them in its own
// sentinel; see the package doc on the error taxonomy.
func ParseKeySet(body []byte) (*josev4.JSONWebKeySet, error) {
	return parseKeySet(body, MaxKeys)
}

// parseKeySet decodes body into a [josev4.JSONWebKeySet]. An empty document is
// rejected; an empty "keys" array is accepted, because a syntactically valid
// response with no keys is the RP's statement rather than a transport failure,
// and the caller reports the absence in its own vocabulary.
//
// Decoding goes through [jose.DecodeJWKSet] so a member this build cannot
// represent is dropped instead of failing the document (RFC 7517 §5). The
// cardinality cap applies to the members the document declares, dropped ones
// included, so it bounds the parse cost of a hostile keyset rather than only
// the survivors.
func parseKeySet(body []byte, maxKeys int) (*josev4.JSONWebKeySet, error) {
	if len(body) == 0 {
		return nil, errors.New("empty body")
	}
	keys, declared, err := jose.DecodeJWKSet(body)
	if declared > maxKeys {
		return nil, fmt.Errorf("jwks contains %d keys (limit %d)", declared, maxKeys)
	}
	if err != nil {
		return nil, fmt.Errorf("parse jwks: %w", err)
	}
	return keys, nil
}

// jwksContentTypes is the response media-type allow-list for a fetched JWKS.
// JWKS servers vary: some emit "application/json", some
// "application/jwk-set+json" (RFC 7517 §8.5). Anything else (text/html from a
// captive portal, application/octet-stream) is rejected so a misrouted
// response cannot be parsed as JSON by accident.
//
//nolint:gochecknoglobals // closed allow-list, intentional package state.
var jwksContentTypes = []string{"application/json", "application/jwk-set+json"}

// ttlFromResponse extracts the freshness lifetime the upstream advertised,
// bounded by ceiling. A zero return leaves the cache's configured TTL in force,
// which is also what a non-positive max-age collapses to: JWKS documents are not
// safe to treat as "no-cache", because revalidation against an unreachable
// upstream is indistinguishable from a key rotation.
//
// The freshness hint belongs to the relying party, so it may only shorten an
// entry's life, never extend it. Without the ceiling an RP advertising a year of
// max-age would pin its keyset in the OP's cache for that year, and a key it
// then leaked or withdrew would keep verifying client assertions — and keep
// receiving outbound encryptions — with no operator-visible signal and no way
// short of a process restart to force a refetch.
func ttlFromResponse(resp *http.Response, ceiling time.Duration) time.Duration {
	maxAge, ok := parseMaxAge(strings.Join(resp.Header.Values("Cache-Control"), ", "))
	if !ok || maxAge <= 0 {
		return 0
	}
	if ceiling > 0 && maxAge > ceiling {
		return ceiling
	}
	return maxAge
}

// parseMaxAge pulls a numeric "max-age" directive out of a Cache-Control header
// value; anything malformed is treated as absent so the caller falls back to
// the configured TTL.
func parseMaxAge(cc string) (time.Duration, bool) {
	parsed := securefetch.ParseCacheControl([]string{cc})
	return parsed.MaxAge, parsed.HasMaxAge
}

// SigningUsable reports whether a JWK whose "use" member is use may verify a
// signature (RFC 7517 §4.2): absent or "sig" only. The declaration is
// binding: a key published as "enc" is the RP's response-encryption key, not a
// verification key, and an unrecognised value names a purpose this OP cannot
// honour.
func SigningUsable(use string) bool {
	return use == "" || use == "sig"
}
