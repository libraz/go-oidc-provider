package i18n

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"strings"
)

// Bundle is the per-locale message map. The structure is a flat
// key→value mapping; nested groups (e.g. "consent.title.long") use
// dotted keys rather than nested objects so the wire form on disk
// matches the lookup surface in code.
type Bundle struct {
	tag      Tag
	messages map[string]string
}

// NewBundle constructs a [Bundle] for tag from messages. The bundle
// takes ownership of messages — the caller MUST NOT mutate the map
// after the call. Empty tag is rejected; the package treats an
// untagged bundle as a programmer bug rather than a runtime fault.
//
// tag is canonicalised through [ParseTag], so a bundle registered as
// "pt-BR" or "pt_br" carries the same [Tag] the resolver derives from
// a cookie or an ui_locales parameter. A tag ParseTag cannot
// canonicalise — blank, or longer than [MaxTagLength] — is rejected
// rather than registered under a key nothing will ever match.
func NewBundle(tag Tag, messages map[string]string) (*Bundle, error) {
	canonical := ParseTag(string(tag))
	if canonical == "" {
		return nil, errUnusableTag(tag)
	}
	if messages == nil {
		messages = map[string]string{}
	}
	return &Bundle{tag: canonical, messages: maps.Clone(messages)}, nil
}

// errUnusableTag reports a tag [ParseTag] refused. The message names
// both bounds because the two rejection causes — blank and over-long —
// are indistinguishable from the returned empty Tag.
func errUnusableTag(tag Tag) error {
	if tag == "" {
		return errors.New("i18n: bundle requires a non-empty tag")
	}
	return fmt.Errorf("i18n: bundle tag %q is unusable: a tag must be non-blank and at most %d bytes",
		string(tag), MaxTagLength)
}

// LoadBundle parses raw as a JSON object whose leaves are strings,
// returning a [Bundle] tagged with tag. Non-string values cause an
// error; the package does not attempt to coerce numbers or booleans
// into message text. tag is canonicalised exactly as [NewBundle] does.
func LoadBundle(tag Tag, raw []byte) (*Bundle, error) {
	canonical := ParseTag(string(tag))
	if canonical == "" {
		return nil, errUnusableTag(tag)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, fmt.Errorf("i18n: parse bundle %q: %w", canonical, err)
	}
	messages := make(map[string]string, len(decoded))
	for k, v := range decoded {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("i18n: bundle %q key %q is %T, want string", canonical, k, v)
		}
		messages[k] = s
	}
	return &Bundle{tag: canonical, messages: messages}, nil
}

// Tag returns the locale tag the bundle was constructed for.
func (b *Bundle) Tag() Tag { return b.tag }

// Merge returns a new [Bundle] tagged with the receiver's tag whose
// messages are the union of the receiver's and over's, with over's
// entries winning on key collisions. Neither input is mutated. A nil
// over yields a defensive copy of the receiver so callers can chain
// without aliasing the original map.
//
// The receiver is treated as the base layer (typically a seed catalogue
// shipped with the library) and over as the overlay (typically an
// embedder-supplied bundle that overrides only the keys the embedder
// cares about). Keys present only in the receiver are preserved; keys
// present only in over are added; keys present in both take over's
// value.
//
// Both bundles MUST share the same [Tag] — Merge mirrors a per-locale
// overlay and combining different locales would silently lose
// information. A tag mismatch returns a non-nil error so a programmer
// bug fails loudly at the call site.
func (b *Bundle) Merge(over *Bundle) (*Bundle, error) {
	if over == nil {
		return &Bundle{tag: b.tag, messages: maps.Clone(b.messages)}, nil
	}
	if b.tag != over.tag {
		return nil, fmt.Errorf("i18n: Bundle.Merge: tag mismatch %q vs %q", b.tag, over.tag)
	}
	merged := make(map[string]string, len(b.messages)+len(over.messages))
	maps.Copy(merged, b.messages)
	maps.Copy(merged, over.messages)
	return &Bundle{tag: b.tag, messages: merged}, nil
}

// Has reports whether the bundle carries a message for key.
func (b *Bundle) Has(key string) bool {
	_, ok := b.messages[key]
	return ok
}

// Get returns the message for key, with `{var}` placeholders
// substituted from data. Missing placeholders are left unsubstituted
// (the literal "{var}" appears in the output) so a translation
// regression surfaces visibly rather than silently swallowing the
// variable.
//
// A missing key returns ("", false). Embedders that want a sentinel
// instead of a boolean can wrap the call in their own helper; the
// package keeps the boolean shape so the caller never receives a
// half-translated string.
func (b *Bundle) Get(key string, data map[string]string) (string, bool) {
	tmpl, ok := b.messages[key]
	if !ok {
		return "", false
	}
	if !strings.Contains(tmpl, "{") || len(data) == 0 {
		return tmpl, true
	}
	return substitute(tmpl, data), true
}

// substitute replaces every "{name}" occurrence in tmpl with
// data["name"]. Missing keys are passed through unchanged. The
// implementation is a hand-written scanner so the input does not
// have to round-trip through text/template (which would force an
// allocation on every Get and mishandle '{' inside translations).
func substitute(tmpl string, data map[string]string) string {
	var b strings.Builder
	b.Grow(len(tmpl))
	i := 0
	for i < len(tmpl) {
		open := strings.IndexByte(tmpl[i:], '{')
		if open < 0 {
			b.WriteString(tmpl[i:])
			break
		}
		open += i
		b.WriteString(tmpl[i:open])
		closeIdx := strings.IndexByte(tmpl[open:], '}')
		if closeIdx < 0 {
			b.WriteString(tmpl[open:])
			break
		}
		closeIdx += open
		key := tmpl[open+1 : closeIdx]
		if val, ok := data[key]; ok {
			b.WriteString(val)
		} else {
			b.WriteString(tmpl[open : closeIdx+1])
		}
		i = closeIdx + 1
	}
	return b.String()
}
