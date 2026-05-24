//go:build apiverify

package apiverify

import "testing"

// 15 negotiates locales; the discovery document advertises
// ui_locales_supported, so a 200 with an issuer confirms it booted.
func TestExample15I18nLocale(t *testing.T) {
	runDiscovery(t, "../../15-i18n-locale", "http://127.0.0.1:8080")
}
