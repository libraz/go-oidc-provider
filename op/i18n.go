package op

import (
	"context"
	"errors"

	"github.com/libraz/go-oidc-provider/internal/i18n"
	"github.com/libraz/go-oidc-provider/op/interaction"
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

// PreferredLocaleStore is the embedder hook the locale resolver
// consults at the head of the §L.2 priority chain (before the
// authorize ui_locales parameter, the __Host-oidc_locale cookie, the
// Accept-Language header, and the default locale). Implementations
// return the saved locale for the supplied subject; an empty Locale
// or a non-nil error is treated as "no preference" so the chain
// continues with the next layer.
//
// Lookup MUST be cheap — the resolver consults it on every authorize
// hit. Backends that need to issue a remote call SHOULD cache the
// result locally; a slow PreferredLocale call adds latency to every
// login screen render.
//
// Stable since v0.1.
type PreferredLocaleStore interface {
	PreferredLocale(ctx context.Context, sub string) (Locale, error)
}

// WithPreferredLocaleStore registers store as the source of per-user
// preferred locales. The store is consulted at the head of the
// resolver chain so a logged-in user's saved locale wins over the
// authorize ui_locales parameter, the cookie, and the Accept-Language
// header.
//
// The option is purely additive: passing a nil store is rejected at
// construction time so a misconfigured option does not silently
// disable the chain. Embedders that want to opt out simply omit the
// option — the resolver falls back to the next layer in the chain.
//
// Stable since v0.1.
func WithPreferredLocaleStore(store PreferredLocaleStore) Option {
	return optionFunc(func(c *config) error {
		if isNilLike(store) {
			return errors.New("op: WithPreferredLocaleStore requires a non-nil store")
		}
		c.preferredLocaleStore = store
		return nil
	})
}

// Resolver is the public view of the locale resolver the Provider
// built from [WithLocale] / [WithDefaultLocale] /
// [WithPreferredLocaleStore]. Embedders fetch it through
// [Provider.LocaleResolver] when they want to render emails, server-
// rendered pages, or out-of-band UIs in the same locale the OP picks
// for /authorize prompts.
//
// Resolver is safe for concurrent use; the Provider builds it once at
// startup and never replaces it.
type Resolver struct {
	inner *i18n.Resolver
}

// ResolveRequest bundles the per-call signals [Resolver.Resolve]
// consults. An embedder rendering an out-of-band surface (email,
// server-rendered admin page) populates the fields it has and leaves
// the rest at their zero values. The resolver walks the chain in
// §L.2 order regardless.
type ResolveRequest struct {
	// Subject is the OP-internal subject identifier for the
	// authenticated user. Empty when the request is unauthenticated;
	// the resolver skips the [PreferredLocaleStore] step in that
	// case.
	Subject string

	// UILocales is the parsed `ui_locales` request parameter. Order
	// is preserved — the resolver tries entries in caller-supplied
	// order.
	UILocales []string

	// Cookie is the value of the __Host-oidc_locale cookie, or empty
	// when absent.
	Cookie string

	// AcceptLanguage is the raw Accept-Language header. The resolver
	// parses q-values internally.
	AcceptLanguage string
}

// Resolve walks the §L.2 priority chain and returns the first
// matching locale. The return value is guaranteed to be a registered
// locale; the chain always terminates at the configured default.
func (r *Resolver) Resolve(ctx context.Context, in ResolveRequest) Locale {
	if r == nil || r.inner == nil {
		return ""
	}
	tag := r.inner.Resolve(ctx, i18n.Request{
		Subject:        in.Subject,
		UILocales:      in.UILocales,
		Cookie:         in.Cookie,
		AcceptLanguage: in.AcceptLanguage,
	})
	return Locale(tag)
}

// Default returns the locale the resolver falls back to when no
// signal in the chain matches. Always populated.
func (r *Resolver) Default() Locale {
	if r == nil || r.inner == nil {
		return ""
	}
	return Locale(r.inner.Default())
}

// Available returns the registered locales in registration order
// (seed bundles first, then [WithLocale] additions). The slice is a
// fresh copy; mutating it does not affect the Resolver.
func (r *Resolver) Available() []Locale {
	if r == nil || r.inner == nil {
		return nil
	}
	tags := r.inner.Available()
	out := make([]Locale, len(tags))
	for i, t := range tags {
		out[i] = Locale(t)
	}
	return out
}

// Message looks up key in locale's merged message catalogue. An exact
// registered locale wins, followed by its registered language subtag (for
// example, "ja-JP" uses "ja"). If that bundle does not contain key, the
// configured default locale is consulted. The boolean is false when neither
// bundle defines key; callers can then apply a surface-specific fallback
// without displaying an internal message key.
//
// Values in data replace matching "{name}" placeholders. Unknown
// placeholders remain visible verbatim, and substituted values are treated as
// plain text rather than recursively interpreted as templates. The returned
// string is raw, unescaped text: HTML templates and other structured-output
// callers MUST apply the appropriate contextual escaping. The default
// interaction.HTMLDriver does so automatically.
//
// Message is safe for concurrent use as long as the caller does not mutate
// data concurrently with the call. The Resolver and registered bundles are
// immutable after [New] returns.
func (r *Resolver) Message(locale Locale, key string, data map[string]string) (string, bool) {
	if r == nil || r.inner == nil {
		return "", false
	}
	return r.inner.Message(i18n.ParseTag(string(locale)), key, data)
}

// wireHTMLDriverTranslator returns a value-copy of driver with the Provider's
// immutable message catalogue connected to every bundled HTMLDriver in the
// default composition. Embedder-supplied translators are authoritative and
// therefore never overwritten.
func wireHTMLDriverTranslator(driver interaction.Driver, resolver *i18n.Resolver) interaction.Driver {
	if driver == nil || resolver == nil {
		return driver
	}
	translator := interaction.MessageTranslator(func(locale, key string, data map[string]string) (string, bool) {
		return resolver.Message(i18n.ParseTag(locale), key, data)
	})
	return injectHTMLTranslator(driver, translator)
}

func injectHTMLTranslator(driver interaction.Driver, translator interaction.MessageTranslator) interaction.Driver {
	switch d := driver.(type) {
	case interaction.HTMLDriver:
		if d.Translator == nil {
			d.Translator = translator
		}
		return d
	case *interaction.HTMLDriver:
		if d == nil || d.Translator != nil {
			return d
		}
		clone := *d
		clone.Translator = translator
		return &clone
	case interaction.TemplateOverlayDriver:
		d.Inner = injectHTMLTranslator(d.Inner, translator)
		return d
	case *interaction.TemplateOverlayDriver:
		if d == nil {
			return d
		}
		clone := *d
		clone.Inner = injectHTMLTranslator(d.Inner, translator)
		return &clone
	default:
		return driver
	}
}

// WithLocale registers a [LocaleBundle] for the given locale. The
// bundle is merged on top of any previously registered bundle for the
// same locale at key granularity: the embedder's keys win on
// collision, but keys the embedder did not supply are preserved from
// the existing layer (the seed en / ja catalogue, or earlier
// [WithLocale] calls). Embedders therefore override only the strings
// they care about — typical brand-aligned overlays only redefine a
// handful of titles or button labels and inherit everything else from
// the seed catalogue.
//
// Layered overrides compose deterministically: repeated [WithLocale]
// calls for the same locale apply in option-list order, so the last
// call wins per key while earlier overrides remain authoritative for
// keys the later call did not redefine.
//
// Locales the seed catalogue does not ship (e.g. "fr", "de") are
// registered as-is on first call and merged on subsequent calls. The
// resolver still falls back to the configured default locale (see
// [WithDefaultLocale]) for any key the new locale's bundles never
// supply.
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
