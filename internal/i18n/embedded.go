package i18n

import "embed"

// embeddedFS carries the v1.0 seed catalogues. The files are
// dotted-key JSON; see [LoadBundle] for the parser. New seed locales
// are added by dropping a `<tag>.json` file alongside en.json /
// ja.json and registering it in [DefaultBundles].
//
//go:embed embedded/*.json
var embeddedFS embed.FS

// DefaultBundles returns the bundles bundled with the library — en
// and ja, both complete since v1.0 so an embedder gets a working
// bilingual OP without registering anything. Embedders that
// want to override an entry register their own bundle for the same
// [Tag] through [op.WithLocale]; the registration order in
// [NewResolver] determines which copy wins.
func DefaultBundles() ([]*Bundle, error) {
	tags := []Tag{English, Japanese}
	bundles := make([]*Bundle, 0, len(tags))
	for _, tag := range tags {
		raw, err := embeddedFS.ReadFile("embedded/" + string(tag) + ".json")
		if err != nil {
			return nil, err
		}
		b, err := LoadBundle(tag, raw)
		if err != nil {
			return nil, err
		}
		bundles = append(bundles, b)
	}
	return bundles, nil
}

// Japanese is the seed Japanese locale. It is exported alongside
// [English] so embedders can reference the constant rather than
// retyping the string.
const Japanese Tag = "ja"
