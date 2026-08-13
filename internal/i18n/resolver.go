package i18n

import (
	"context"
	"errors"
	"strconv"
	"strings"
)

const maxLocaleCookieLen = 64

// Resolver picks a [Tag] for an inbound request by walking the
// package's locale priority chain. The resolver is constructed
// once at OP startup; it is safe for concurrent use.
type Resolver struct {
	bundles map[Tag]*Bundle
	order   []Tag
	defTag  Tag
	prefs   PreferredLocaleStore
}

// PreferredLocaleStore is the optional embedder hook that returns
// the per-user preferred locale. The interface is structural so any
// store satisfying the shape is accepted; the orchestrator passes a
// nil store when the embedder did not implement the hook.
//
// Lookup MUST be cheap (the resolver consults it on every authorize
// hit). Errors are treated as "no preference" rather than failures
// — the locale chain is best-effort and an unavailable backend
// should not block authentication.
type PreferredLocaleStore interface {
	PreferredLocale(ctx context.Context, sub string) (Tag, error)
}

// NewResolver returns a [Resolver] over the supplied bundles. Bundle
// registration order is preserved so the matcher prefers
// caller-supplied locales over the embedded default when the priority
// chain runs out.
//
// defTag is canonicalised through [ParseTag] and MUST name a
// registered bundle; a default nothing serves is a configuration error
// rather than a silent redirection, because [Resolver.Default] is
// reported to embedders and terminates every lookup chain. Only an
// unset defTag defers the choice to the resolver, which then prefers
// [English] and falls back to the first registered bundle.
func NewResolver(defTag Tag, bundles ...*Bundle) (*Resolver, error) {
	if len(bundles) == 0 {
		return nil, errors.New("i18n: NewResolver requires at least one bundle")
	}
	r := &Resolver{
		bundles: make(map[Tag]*Bundle, len(bundles)),
		order:   make([]Tag, 0, len(bundles)),
	}
	for _, b := range bundles {
		if b == nil {
			return nil, errors.New("i18n: bundle is nil")
		}
		if _, dup := r.bundles[b.Tag()]; dup {
			return nil, errors.New("i18n: duplicate bundle tag " + string(b.Tag()))
		}
		r.bundles[b.Tag()] = b
		r.order = append(r.order, b.Tag())
	}
	if strings.TrimSpace(string(defTag)) != "" {
		canonical := ParseTag(string(defTag))
		if canonical == "" || r.bundles[canonical] == nil {
			return nil, errors.New("i18n: default locale " + string(defTag) + " has no registered bundle")
		}
		r.defTag = canonical
		return r, nil
	}
	if r.bundles[English] != nil {
		r.defTag = English
	} else {
		r.defTag = r.order[0]
	}
	return r, nil
}

// WithPreferredLocaleStore installs prefs as the [PreferredLocaleStore]
// the resolver consults at the head of the priority chain. The call
// returns the receiver so options can be chained.
func (r *Resolver) WithPreferredLocaleStore(prefs PreferredLocaleStore) *Resolver {
	r.prefs = prefs
	return r
}

// Default returns the resolver's default tag.
func (r *Resolver) Default() Tag { return r.defTag }

// Bundle returns the bundle serving tag under the same matching rule
// [Resolver.Match] applies, or the default bundle when tag matches
// nothing. The second return reports whether tag matched so callers
// that want to detect a fall-back can branch.
func (r *Resolver) Bundle(tag Tag) (*Bundle, bool) {
	if matched, ok := r.match(tag); ok {
		return r.bundles[matched], true
	}
	return r.bundles[r.defTag], false
}

// Message returns key from the first bundle along tag's lookup chain
// that defines it. The chain is tag's own [Tag.Fallback] sequence
// ("pt-BR" → "pt-br" → "pt"), then the configured default locale's,
// and finally the library's [English] catalogue — so a partial bundle
// serves the keys it translates and inherits the rest, and a partial
// bundle chosen as the *default* inherits from English rather than
// emitting empty strings. The boolean is false only when no bundle in
// the chain defines key.
//
// Placeholder substitution follows [Bundle.Get]: values from data replace
// matching "{name}" tokens, unknown placeholders remain visible verbatim,
// and data values are never interpreted as templates. The returned string is
// plain text; callers rendering HTML or another structured format own the
// corresponding output escaping.
func (r *Resolver) Message(tag Tag, key string, data map[string]string) (string, bool) {
	if r == nil || key == "" {
		return "", false
	}
	for _, b := range r.messageChain(tag) {
		if message, ok := b.Get(key, data); ok {
			return message, true
		}
	}
	return "", false
}

// messageChain returns the bundles [Resolver.Message] consults for tag,
// in priority order and without repeats: the tag's own lookup chain,
// then the configured default's, then English. Tiers are appended
// whole rather than stopping at the first registered bundle, because a
// registered bundle may be partial — the point of the chain is that a
// key the more specific bundle omits is still served.
func (r *Resolver) messageChain(tag Tag) []*Bundle {
	seen := make(map[Tag]struct{}, 4)
	chain := make([]*Bundle, 0, 4)
	for _, tier := range [...]Tag{tag, r.defTag, English} {
		for _, candidate := range ParseTag(string(tier)).Fallback() {
			if _, dup := seen[candidate]; dup {
				continue
			}
			seen[candidate] = struct{}{}
			if b := r.bundles[candidate]; b != nil {
				chain = append(chain, b)
			}
		}
	}
	return chain
}

// Available returns the tags registered with the resolver in
// registration order. The slice is a fresh copy; callers may mutate
// it without affecting the resolver.
func (r *Resolver) Available() []Tag {
	out := make([]Tag, len(r.order))
	copy(out, r.order)
	return out
}

// Request bundles the per-call signals the resolver consults. The
// fields mirror the priority chain step-by-step; an embedder that does
// not have a particular signal leaves the corresponding field at
// its zero value.
type Request struct {
	// Subject is the OP subject identifier of the authenticated user,
	// when known. Empty for unauthenticated requests; the resolver
	// skips the [PreferredLocaleStore] step when unset.
	Subject string

	// UILocales is the space-separated `ui_locales` authorize
	// parameter, split into individual tags. Order is preserved —
	// the resolver tries entries in caller-supplied order.
	UILocales []string

	// Cookie is the value of the __Host-oidc_locale cookie. Empty
	// when the cookie is absent.
	Cookie string

	// AcceptLanguage is the raw Accept-Language header. The resolver
	// parses q-values internally; the caller does not have to
	// pre-split.
	AcceptLanguage string
}

// Resolve walks the priority chain and returns the first matching
// tag. The chain always terminates at the default tag, so the
// return value is guaranteed to be a registered locale.
//
//nolint:gocognit // Resolve walks the fixed locale priority chain (prefs, ui_locales, cookie, Accept-Language, default) in flat shape.
func (r *Resolver) Resolve(ctx context.Context, in Request) Tag {
	if r.prefs != nil && in.Subject != "" {
		if tag, err := r.prefs.PreferredLocale(ctx, in.Subject); err == nil {
			if matched, ok := r.match(tag); ok {
				return matched
			}
		}
	}
	for _, raw := range in.UILocales {
		if matched, ok := r.match(Tag(raw)); ok {
			return matched
		}
	}
	if validLocaleCookie(in.Cookie) {
		if matched, ok := r.match(Tag(in.Cookie)); ok {
			return matched
		}
	}
	for _, raw := range parseAcceptLanguage(in.AcceptLanguage) {
		if matched, ok := r.match(Tag(raw)); ok {
			return matched
		}
	}
	return r.defTag
}

// Match reports the registered tag that would serve the supplied tag,
// applying the same rule [Resolver.Resolve] uses inside the chain: the
// tag is canonicalised and then looked up along its BCP 47 fallback
// chain, so "PT-BR" selects a registered "pt-br" bundle and "ja-JP"
// selects "ja". The returned tag is always one of
// [Resolver.Available]; the boolean is false when nothing matched,
// which callers persisting a user's choice use to reject a tag the
// resolver would later skip.
func (r *Resolver) Match(tag Tag) (Tag, bool) {
	if r == nil {
		return "", false
	}
	return r.match(tag)
}

// match resolves tag against the registered bundles. It is the single
// entry point for every locale signal the resolver consults, so it
// owns both halves of the rule: the tag is canonicalised through
// [ParseTag] — callers hand it whatever the wire, a cookie or an
// embedder supplied, in whatever case and with either separator — and
// the canonical form is then looked up along its [Tag.Fallback] chain,
// most specific first, so "pt-BR" selects a registered "pt-br" bundle
// and, failing that, a registered "pt" one. An empty input or no match
// along the whole chain returns ("", false).
func (r *Resolver) match(tag Tag) (Tag, bool) {
	for _, candidate := range ParseTag(string(tag)).Fallback() {
		if _, ok := r.bundles[candidate]; ok {
			return candidate, true
		}
	}
	return "", false
}

func validLocaleCookie(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > maxLocaleCookieLen {
		return false
	}
	for i := range len(raw) {
		c := raw[i]
		if (c >= 'A' && c <= 'Z') ||
			(c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') ||
			c == '-' || c == '_' {
			continue
		}
		return false
	}
	return true
}

// parseAcceptLanguage extracts the language tags from the raw
// Accept-Language header in q-value-descending order. The parser is
// intentionally minimal: it splits on ',' and trims optional ';q=N'
// suffixes, sorting only by descending q so the resolver sees the
// caller's most-preferred entry first. Malformed q values fall back
// to 1.0 — the package errs toward more matches over fewer.
//
//nolint:gocognit // parseAcceptLanguage is a flat RFC 7231 q-value parser; the branch count tracks the grammar.
func parseAcceptLanguage(raw string) []string {
	if raw = strings.TrimSpace(raw); raw == "" {
		return nil
	}
	type entry struct {
		tag string
		q   float64
	}
	var entries []entry
	for _, part := range strings.Split(raw, ",") {
		if len(entries) >= maxAcceptLanguageEntries {
			break
		}
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		q := 1.0
		tag := part
		if semi := strings.IndexByte(part, ';'); semi >= 0 {
			tag = strings.TrimSpace(part[:semi])
			q = parseQValue(part[semi+1:])
		}
		if tag == "" || len(tag) > MaxTagLength || q <= 0 {
			continue
		}
		entries = append(entries, entry{tag: tag, q: q})
	}
	// Stable sort by descending q so the caller's preference order
	// is preserved among equal-q entries.
	for i := 1; i < len(entries); i++ {
		for j := i; j > 0 && entries[j].q > entries[j-1].q; j-- {
			entries[j], entries[j-1] = entries[j-1], entries[j]
		}
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.tag)
	}
	return out
}

const maxAcceptLanguageEntries = 20

// parseQValue extracts the float from a "q=N" / "q=0.7" trailer.
// Anything the parser cannot interpret returns 1.0 — see the note
// on parseAcceptLanguage about the err-toward-more posture.
func parseQValue(trailer string) float64 {
	trailer = strings.TrimSpace(trailer)
	if !strings.HasPrefix(trailer, "q=") {
		return 1.0
	}
	q, err := strconv.ParseFloat(strings.TrimSpace(trailer[2:]), 64)
	if err != nil || q < 0 {
		return 1.0
	}
	if q > 1 {
		q = 1
	}
	return q
}
