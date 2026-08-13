package i18n

import (
	"strings"
)

// Tag is the OP's BCP 47 language tag. It is a normalised string
// — lowercase, hyphen-separated — so equality comparisons work
// without a separate Equal method. The package never round-trips
// through golang.org/x/text/language; the heavy machinery is not
// worth the dep at the v1.0 surface area, and BCP 47 prefix matching
// is enough for the resolver's priority chain.
type Tag string

// English is the library default fallback. It is the locale of the
// canonical message catalogue and the value [DefaultTag] returns
// when no other tag is registered.
const English Tag = "en"

// MaxTagLength bounds locale tags accepted from HTTP surfaces. Valid
// BCP 47 tags used by the resolver are far shorter; the cap keeps
// oversized Accept-Language / cookie values from driving avoidable CPU
// and allocation work.
const MaxTagLength = 48

// ParseTag canonicalises raw into a [Tag]. Whitespace is trimmed,
// case is folded to lower, and the BCP 47 separator is normalised
// to '-'. Empty input returns the empty Tag, not [English]; the
// caller decides whether an empty tag should fall back.
//
// ParseTag is the package's single normalisation point. Every Tag that
// reaches a resolver's bundle map — whether it arrives from bundle
// registration, the configured default, a cookie, an Accept-Language
// header or an ui_locales parameter — passes through it, so a locale
// that can be registered is a locale that can be selected. Callers
// MUST NOT hand-roll case folding or separator handling; a tag built by
// converting a string directly is only usable if it already happens to
// be in the form ParseTag produces.
func ParseTag(raw string) Tag {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > MaxTagLength {
		return ""
	}
	out := make([]byte, 0, len(raw))
	for i := range len(raw) {
		c := raw[i]
		switch {
		case c >= 'A' && c <= 'Z':
			out = append(out, c+('a'-'A'))
		case c == '_':
			out = append(out, '-')
		default:
			out = append(out, c)
		}
	}
	return Tag(out)
}

// Language returns the primary language subtag — the bytes before
// the first '-'. "ja-JP" → "ja"; "en" → "en"; the empty Tag returns
// the empty Tag. It is the last entry [Tag.Fallback] yields.
func (t Tag) Language() Tag {
	if i := strings.IndexByte(string(t), '-'); i >= 0 {
		return t[:i]
	}
	return t
}

// Fallback returns the tag's lookup chain in most-specific-first
// order, following the RFC 4647 §3.4 "Lookup" scheme: the rightmost
// subtag is dropped one at a time until only the primary language
// subtag remains, and a truncation that would leave a trailing
// single-character subtag drops that subtag too, because a singleton
// ("x" opening a private-use sequence, "u" opening a Unicode
// extension) is a prefix marker rather than a locale of its own.
//
// The receiver is always the first entry, so a caller can walk the
// result as the complete candidate list:
//
//	"pt-br"      → ["pt-br", "pt"]
//	"zh-hant-tw" → ["zh-hant-tw", "zh-hant", "zh"]
//	"en"         → ["en"]
//
// Truncation is all Fallback does; the receiver is expected to be in
// the form [ParseTag] produces. The empty Tag yields nil.
func (t Tag) Fallback() []Tag {
	if t == "" {
		return nil
	}
	out := []Tag{t}
	cur := t
	for {
		i := strings.LastIndexByte(string(cur), '-')
		if i < 0 {
			return out
		}
		cur = cur[:i]
		if j := strings.LastIndexByte(string(cur), '-'); j >= 0 && len(cur)-j == 2 {
			cur = cur[:j]
		} else if len(cur) < 2 {
			// A bare singleton is not a language; stop rather than
			// offering it as a candidate.
			return out
		}
		out = append(out, cur)
	}
}

// String returns the canonical BCP 47 form of t.
func (t Tag) String() string { return string(t) }
