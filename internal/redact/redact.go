package redact

import (
	"context"
	"log/slog"
	"strings"
)

// Sentinel is the fixed string that replaces a redacted attribute
// value. The value is intentionally short so a redacted record is
// trivially greppable; the string is a constant so test fixtures can
// match on it without a moving target.
const Sentinel = "[REDACTED]"

// Sensitive is the closed list of attribute keys (lowercased) the
// redactor matches verbatim. Matching is case-insensitive and
// structural — an attribute group called "code" matches even if the
// caller wrote it as "Code". The list covers the OIDC / OAuth
// credential-bearing fields the OP itself produces (access_token,
// refresh_token, id_token, client_secret, code, code_verifier,
// password) plus the request-binding fields whose disclosure breaks
// CSRF / replay defences (state, nonce).
//
// Keys MAY appear with surrounding HTTP-header punctuation (`Set-
// Cookie`, `Authorization`); the matcher canonicalises hyphens and
// underscores so a single entry covers both forms.
//
//nolint:gochecknoglobals // closed enumeration of credential-bearing OIDC / OAuth fields.
var Sensitive = []string{
	"access_token",
	"refresh_token",
	"id_token",
	"client_secret",
	"code",
	"code_verifier",
	"password",
	"state",
	"nonce",
	"dpop",
	"dpop_proof",
	"authorization",
	"cookie",
	"set_cookie",
	"registration_access_token",
	"initial_access_token",
	"request",
	"request_uri",
	"assertion",
	"client_assertion",
}

// sensitiveSubstrings is the closed list of needles that mark a key as
// sensitive when they appear *anywhere* inside the canonicalised name.
// The list catches naming variants the exact-match catalogue cannot
// enumerate (e.g. `password_hash`, `new_refresh_token`,
// `client_secret_jwt`, `bearer_token`). Substring matching trades a
// little precision for a regression-resistant default; legitimate
// false-positives are covered by [substringAllowlist].
//
//nolint:gochecknoglobals // closed enumeration; mirrors Sensitive.
var sensitiveSubstrings = []string{
	"secret",
	"token",
	"password",
	"assertion",
	"bearer",
	"private_key",
	"pwd",
	"passcode",
}

// substringAllowlist is the canonical-form catalogue of keys that
// would otherwise trip [sensitiveSubstrings] but are known to carry
// only category metadata, never the secret itself. The list is
// intentionally small; embedders wanting broader exemption SHOULD
// route through their own [slog.HandlerOptions.ReplaceAttr].
//
//nolint:gochecknoglobals // closed enumeration paired with sensitiveSubstrings.
var substringAllowlist = []string{
	"keypair_kid",
	"token_type",
	"secret_type",
	"token_endpoint",
	"token_endpoint_auth_method",
	"token_endpoint_auth_signing_alg",
	"id_token_signed_response_alg",
	"id_token_encrypted_response_alg",
	"id_token_encrypted_response_enc",
	"userinfo_signed_response_alg",
	"request_object_signing_alg",
	"introspection_endpoint",
	"revocation_endpoint",
}

// IsSensitive reports whether key (after canonicalisation) names a
// sensitive attribute. Callers SHOULD use this helper rather than
// re-implementing the comparison so the catalogue stays single-source.
//
// The match is layered: an exact-match against [Sensitive] wins
// first; otherwise a substring-match against [sensitiveSubstrings]
// is consulted, with [substringAllowlist] suppressing known
// false-positives.
func IsSensitive(key string) bool {
	canon := canonicalise(key)
	if canon == "" {
		return false
	}
	for _, s := range Sensitive {
		if canon == s {
			return true
		}
	}
	for _, allow := range substringAllowlist {
		if canon == allow {
			return false
		}
	}
	for _, needle := range sensitiveSubstrings {
		if strings.Contains(canon, needle) {
			return true
		}
	}
	return false
}

// canonicalise lowercases s and rewrites hyphens to underscores so
// the matcher treats `Set-Cookie`, `set_cookie`, and `set-cookie`
// uniformly.
func canonicalise(s string) string {
	if s == "" {
		return ""
	}
	out := make([]byte, 0, len(s))
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
			out = append(out, c+('a'-'A'))
		case c == '-':
			out = append(out, '_')
		default:
			out = append(out, c)
		}
	}
	return string(out)
}

// ReplaceAttr is the [slog.HandlerOptions.ReplaceAttr] hook that
// performs single-attribute redaction. It is exposed for embedders
// who construct their own [slog.Handler] and wish to compose the
// redaction with additional rewrites.
//
// Group attributes are recursed into by the slog runtime, so this
// hook does not have to descend manually — slog passes each leaf
// attribute through ReplaceAttr separately.
func ReplaceAttr(_ []string, a slog.Attr) slog.Attr {
	if !IsSensitive(a.Key) {
		return a
	}
	return slog.String(a.Key, Sentinel)
}

// WrapHandler returns a [slog.Handler] that runs every record
// through the redactor before delegating to next. The wrapper is
// idempotent: wrapping an already-wrapped handler is safe and the
// inner copy short-circuits the second pass.
//
// A nil next collapses to [discardHandler] so the redactor cannot
// be the cause of a downstream nil-deref. Embedders that pass a nil
// handler get a silent logger; that is preferable to a panic from a
// library that should never be the failure mode of an HTTP path.
func WrapHandler(next slog.Handler) slog.Handler {
	if next == nil {
		next = discardHandler{}
	}
	if _, ok := next.(*handler); ok {
		return next
	}
	return &handler{next: next}
}

// discardHandler drops every record. It is the fall-back used when
// [WrapHandler] is called with nil so a programmer bug surfaces as
// silence rather than a runtime panic. The type is unexported so the
// fall-back is the only path that constructs it.
type discardHandler struct{}

func (discardHandler) Enabled(_ context.Context, _ slog.Level) bool  { return false }
func (discardHandler) Handle(_ context.Context, _ slog.Record) error { return nil }
func (d discardHandler) WithAttrs(_ []slog.Attr) slog.Handler        { return d }
func (d discardHandler) WithGroup(_ string) slog.Handler             { return d }

// handler is the slog.Handler shim. The struct is intentionally
// minimal — the heavy lifting is in redactRecord — so adding a new
// sensitive key is a one-line edit to [Sensitive].
type handler struct {
	next slog.Handler
}

// Enabled mirrors the wrapped handler so the redactor never enables
// records the underlying handler would have dropped.
func (h *handler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

// Handle redacts the record's attributes and delegates to the
// underlying handler. The record is cloned so callers that retain a
// pointer to the original see the unredacted form (slog hands us a
// value, not a pointer, so this is automatic).
func (h *handler) Handle(ctx context.Context, r slog.Record) error {
	return h.next.Handle(ctx, redactRecord(r))
}

// WithAttrs propagates attribute attachment, redacting on the way
// in so attached attributes never leak through the underlying
// handler unmasked.
func (h *handler) WithAttrs(attrs []slog.Attr) slog.Handler {
	out := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		out[i] = redactAttr(a)
	}
	return &handler{next: h.next.WithAttrs(out)}
}

// WithGroup propagates group nesting unchanged. Group names are not
// secrets; per-leaf redaction inside the group still runs through
// Handle.
func (h *handler) WithGroup(name string) slog.Handler {
	return &handler{next: h.next.WithGroup(name)}
}

// redactRecord rebuilds r with each attribute passed through
// redactAttr. The clone preserves time / level / message / pc and
// only touches the attribute slice, matching the slog convention
// for transformations.
func redactRecord(r slog.Record) slog.Record {
	clone := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	r.Attrs(func(a slog.Attr) bool {
		clone.AddAttrs(redactAttr(a))
		return true
	})
	return clone
}

// redactAttr applies the redactor to a single attribute and recurses
// into group values. The recursion is bounded by the caller-supplied
// nesting; slog itself bounds the depth, so a malicious input cannot
// induce unbounded recursion here.
func redactAttr(a slog.Attr) slog.Attr {
	if a.Value.Kind() == slog.KindGroup {
		group := a.Value.Group()
		out := make([]slog.Attr, len(group))
		for i, child := range group {
			out[i] = redactAttr(child)
		}
		return slog.Attr{Key: a.Key, Value: slog.GroupValue(out...)}
	}
	if IsSensitive(a.Key) {
		return slog.String(a.Key, Sentinel)
	}
	return a
}

// Mask rewrites recognised `key=value` pairs in s with the sentinel.
// It is intended for free-form strings (typically URLs or HTTP
// header values) that embed query parameters before they reach a
// log call. The function is conservative: it only touches pairs
// whose key matches the [Sensitive] catalogue, leaves the
// surrounding text intact, and never decodes percent-escapes (so a
// URL with `%26` inside a value is treated as a single value).
//
// The implementation is a hand-written parser rather than
// net/url.ParseQuery so the exact byte layout of the input is
// preserved: callers logging "code=abc&state=xyz" see
// "code=[REDACTED]&state=[REDACTED]" rather than a re-encoded form.
func Mask(s string) string {
	if s == "" {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		j := nextPairEnd(s, i)
		writePair(&b, s[i:j])
		if j == len(s) {
			break
		}
		b.WriteByte(s[j])
		i = j + 1
	}
	return b.String()
}

// nextPairEnd returns the index of the next pair-terminator starting
// at or after i. Pairs are terminated by '&', '?', ',', ';', or
// whitespace — the separators that appear in URL query strings,
// Cookie headers, and free-form log strings respectively. The
// query-string introducer '?' is treated as a terminator so a
// logged URL like ".../cb?code=v" splits the path from the query
// before the pair scanner runs.
func nextPairEnd(s string, i int) int {
	for j := i; j < len(s); j++ {
		switch s[j] {
		case '&', '?', ',', ';', ' ', '\t':
			return j
		}
	}
	return len(s)
}

// writePair extracts the key=value split from pair, replaces the
// value with the sentinel when the key is sensitive, and writes the
// result to b. Pairs without an `=` are written verbatim — they are
// not key=value pairs and the masker has no opinion on them.
func writePair(b *strings.Builder, pair string) {
	eq := strings.IndexByte(pair, '=')
	if eq <= 0 {
		b.WriteString(pair)
		return
	}
	key := strings.TrimSpace(pair[:eq])
	if !IsSensitive(key) {
		b.WriteString(pair)
		return
	}
	b.WriteString(pair[:eq+1])
	b.WriteString(Sentinel)
}
