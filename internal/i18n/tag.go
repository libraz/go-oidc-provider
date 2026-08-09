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
// the empty Tag. The helper is the only fall-back the matcher uses
// when an exact tag does not match a registered locale.
func (t Tag) Language() Tag {
	if i := strings.IndexByte(string(t), '-'); i >= 0 {
		return t[:i]
	}
	return t
}

// String returns the canonical BCP 47 form of t.
func (t Tag) String() string { return string(t) }
