// Package i18n is the OP's locale resolver and message catalogue.
//
// The package answers two questions every user-facing surface (login
// SPA, consent screen, end-session page, email templates) needs to
// answer up front:
//
//  1. Which locale should we render this request in?
//  2. What does message key "X" say in that locale?
//
// The resolver walks the priority chain from design 002 §L.2:
//
//	UserStore.PreferredLocale(sub)
//	→ ui_locales authorize parameter
//	→ __Host-oidc_locale cookie
//	→ Accept-Language HTTP header
//	→ WithDefaultLocale (defaults to "en")
//
// The first locale that matches a registered [Bundle] wins; the
// chain is exhaustive so a request without any of these signals
// always lands on the default. Embedders that want to bypass the
// resolver entirely can hand-build a [Tag] and call [Bundle.Get]
// directly.
//
// Message catalogues are simple JSON files: the leaves are strings
// with `{var}` placeholders that [Bundle.Get] substitutes from the
// supplied data map. v1.0 deliberately avoids ICU MessageFormat —
// the design 002 §L.4 plural / gender support lands once the
// surface area justifies the dependency.
package i18n
