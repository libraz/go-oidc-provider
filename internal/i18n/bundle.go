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
func NewBundle(tag Tag, messages map[string]string) (*Bundle, error) {
	if tag == "" {
		return nil, errors.New("i18n: bundle requires a non-empty tag")
	}
	if messages == nil {
		messages = map[string]string{}
	}
	return &Bundle{tag: tag, messages: maps.Clone(messages)}, nil
}

// LoadBundle parses raw as a JSON object whose leaves are strings,
// returning a [Bundle] tagged with tag. Non-string values cause an
// error; the package does not attempt to coerce numbers or booleans
// into message text.
func LoadBundle(tag Tag, raw []byte) (*Bundle, error) {
	if tag == "" {
		return nil, errors.New("i18n: bundle requires a non-empty tag")
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return nil, fmt.Errorf("i18n: parse bundle %q: %w", tag, err)
	}
	messages := make(map[string]string, len(decoded))
	for k, v := range decoded {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("i18n: bundle %q key %q is %T, want string", tag, k, v)
		}
		messages[k] = s
	}
	return &Bundle{tag: tag, messages: messages}, nil
}

// Tag returns the locale tag the bundle was constructed for.
func (b *Bundle) Tag() Tag { return b.tag }

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
