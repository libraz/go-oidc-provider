package rpjwks

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/libraz/go-oidc-provider/internal/jose"
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

// isJSONContentType reports whether ct is a JSON-ish media type. JWKS servers
// vary: some emit "application/json", some "application/jwk-set+json" (RFC 7517
// §8.5). Both are accepted; anything else (text/html from a captive portal,
// application/octet-stream) is rejected so a misrouted response cannot be
// parsed as JSON by accident.
func isJSONContentType(ct string) bool {
	if ct == "" {
		return false
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	ct = strings.TrimSpace(strings.ToLower(ct))
	return ct == "application/json" || ct == "application/jwk-set+json"
}

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
	maxAge, ok := parseMaxAge(resp.Header.Get("Cache-Control"))
	if !ok || maxAge <= 0 {
		return 0
	}
	if ceiling > 0 && maxAge > ceiling {
		return ceiling
	}
	return maxAge
}

// parseMaxAge pulls a numeric "max-age" directive out of a Cache-Control header
// value. The parser is intentionally minimal: it accepts the canonical form
// ("max-age=300") and ignores quoted forms or leading whitespace. Anything more
// elaborate is silently treated as absent so the caller falls back to the
// configured TTL.
func parseMaxAge(cc string) (time.Duration, bool) {
	if cc == "" {
		return 0, false
	}
	for _, raw := range strings.Split(cc, ",") {
		token := strings.TrimSpace(strings.ToLower(raw))
		const prefix = "max-age="
		if !strings.HasPrefix(token, prefix) {
			continue
		}
		secs, err := parseUnsignedSeconds(token[len(prefix):])
		if err != nil {
			return 0, false
		}
		return time.Duration(secs) * time.Second, true
	}
	return 0, false
}

// parseUnsignedSeconds decodes a non-negative decimal integer, returning an
// error on any non-digit input. Used by [parseMaxAge] so the caller does not
// depend on strconv directly.
func parseUnsignedSeconds(s string) (int64, error) {
	if s == "" {
		return 0, errors.New("empty")
	}
	var out int64
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("non-digit %q", c)
		}
		out = out*10 + int64(c-'0')
		if out > 1<<31 {
			return 0, errors.New("overflow")
		}
	}
	return out, nil
}
