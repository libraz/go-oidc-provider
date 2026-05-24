//go:build apiverify

package apiverify

import "testing"

// 15 registers en + ja (seed) plus a custom fr; the deliverable is that the
// discovery document advertises all three under ui_locales_supported.
func TestExample15I18nLocale(t *testing.T) {
	runDiscoveryAssert(t, "../../15-i18n-locale", "http://127.0.0.1:8080",
		[]string{`"ui_locales_supported"`, `"fr"`, `"ja"`}, nil)
}
