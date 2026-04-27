package i18n

import (
	"context"
	"errors"
	"strconv"
	"strings"
)

// Resolver picks a [Tag] for an inbound request by walking the
// priority chain from design 002 §L.2. The resolver is constructed
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

// NewResolver returns a [Resolver] over the supplied bundles. The
// first bundle whose [Tag] equals defTag is treated as the default;
// when defTag is unset or unmatched, [English] is used. Bundle
// registration order is preserved so the matcher prefers
// caller-supplied locales over the embedded default when the
// priority chain runs out.
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
	r.defTag = defTag
	if r.defTag == "" || r.bundles[r.defTag] == nil {
		if r.bundles[English] != nil {
			r.defTag = English
		} else {
			r.defTag = r.order[0]
		}
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

// Bundle returns the bundle for tag, or the default bundle when tag
// is not registered. The second return reports whether tag matched
// directly so callers that want to detect a fall-back can branch.
func (r *Resolver) Bundle(tag Tag) (*Bundle, bool) {
	if b, ok := r.bundles[tag]; ok {
		return b, true
	}
	return r.bundles[r.defTag], false
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
// fields mirror design 002 §L.2 step-by-step; an embedder that does
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
func (r *Resolver) Resolve(ctx context.Context, in Request) Tag {
	if r.prefs != nil && in.Subject != "" {
		if tag, err := r.prefs.PreferredLocale(ctx, in.Subject); err == nil {
			if matched, ok := r.match(tag); ok {
				return matched
			}
		}
	}
	for _, raw := range in.UILocales {
		if matched, ok := r.match(ParseTag(raw)); ok {
			return matched
		}
	}
	if matched, ok := r.match(ParseTag(in.Cookie)); ok {
		return matched
	}
	for _, raw := range parseAcceptLanguage(in.AcceptLanguage) {
		if matched, ok := r.match(ParseTag(raw)); ok {
			return matched
		}
	}
	return r.defTag
}

// match resolves tag against the registered bundles. An exact match
// wins; failing that, the language subtag is tried so "ja-JP" hits
// the "ja" bundle. An empty input or no match returns ("", false).
func (r *Resolver) match(tag Tag) (Tag, bool) {
	if tag == "" {
		return "", false
	}
	if _, ok := r.bundles[tag]; ok {
		return tag, true
	}
	lang := tag.Language()
	if lang == tag {
		return "", false
	}
	if _, ok := r.bundles[lang]; ok {
		return lang, true
	}
	return "", false
}

// parseAcceptLanguage extracts the language tags from the raw
// Accept-Language header in q-value-descending order. The parser is
// intentionally minimal: it splits on ',' and trims optional ';q=N'
// suffixes, sorting only by descending q so the resolver sees the
// caller's most-preferred entry first. Malformed q values fall back
// to 1.0 — the package errs toward more matches over fewer.
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
		if tag == "" || q <= 0 {
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
