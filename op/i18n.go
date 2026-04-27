package op

import (
	"errors"

	"github.com/libraz/go-oidc-provider/internal/i18n"
)

// Locale is the OP's BCP 47 language tag. The type is a thin alias
// over the internal representation so embedders can declare locale
// constants alongside their other op options without importing
// internal packages.
type Locale string

// LocaleEnglish and LocaleJapanese are the seed locales the library
// ships with. Embedders MAY register additional locales through
// [WithLocale]; the existing entries are still served until the
// override is registered.
const (
	LocaleEnglish  Locale = "en"
	LocaleJapanese Locale = "ja"
)

// String returns the canonical BCP 47 form of the locale. The method
// makes Locale satisfy [fmt.Stringer] so log statements emit a clean
// representation without an explicit cast.
func (l Locale) String() string { return string(l) }

// LocaleBundle is a per-locale message map supplied by the embedder.
// The exposed surface is intentionally narrow: a constructor that
// accepts a flat key→string map. Embedders that ship a JSON file
// pass the parsed contents through [LocaleBundleFromMap] so the
// internal validation runs.
type LocaleBundle struct {
	internal *i18n.Bundle
}

// LocaleBundleFromMap returns a [LocaleBundle] for locale from the
// supplied messages. The map is cloned so a later mutation by the
// caller does not race with the OP. Empty messages are accepted —
// embedders may register a locale stub and fill it in later.
func LocaleBundleFromMap(locale Locale, messages map[string]string) (LocaleBundle, error) {
	if locale == "" {
		return LocaleBundle{}, errors.New("op: LocaleBundle requires a non-empty locale")
	}
	b, err := i18n.NewBundle(i18n.Tag(locale), messages)
	if err != nil {
		return LocaleBundle{}, err
	}
	return LocaleBundle{internal: b}, nil
}

// Locale returns the locale tag the bundle was constructed for. The
// accessor exists so embedders that build a slice of bundles can
// assert on the tags before threading them through [WithLocale].
func (b LocaleBundle) Locale() Locale {
	if b.internal == nil {
		return ""
	}
	return Locale(b.internal.Tag())
}

// WithDefaultLocale sets the locale the resolver falls back to when
// no signal in the priority chain (ui_locales / cookie /
// Accept-Language / preferred locale) matches a registered bundle.
// Defaults to [LocaleEnglish]; embedders that ship an OP for a
// locale-specific audience SHOULD set this so a request without any
// locale hint lands on the right language.
//
// The supplied locale MUST be registered through [WithLocale] (or
// be one of the seed locales — en / ja). A default that is not
// registered is rejected at construction time.
//
// Stable since v0.1.
func WithDefaultLocale(locale Locale) Option {
	return optionFunc(func(c *config) error {
		if locale == "" {
			return errors.New("op: WithDefaultLocale requires a non-empty locale")
		}
		c.defaultLocale = locale
		return nil
	})
}

// WithLocale registers (or overrides) a [LocaleBundle] for the given
// locale. The bundle replaces any previously registered bundle for
// the same locale, including the seed en / ja catalogues, so
// embedders can swap in their own brand-aligned strings.
//
// At least one bundle for the configured default locale (see
// [WithDefaultLocale]) MUST be registered — either via this option
// or implicitly through the seed library bundles.
//
// Stable since v0.1.
func WithLocale(bundle LocaleBundle) Option {
	return optionFunc(func(c *config) error {
		if bundle.internal == nil {
			return errors.New("op: WithLocale requires a non-empty bundle")
		}
		c.localeBundles = append(c.localeBundles, bundle)
		return nil
	})
}
