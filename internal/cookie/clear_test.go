package cookie_test

import (
	"testing"

	"github.com/libraz/go-oidc-provider/internal/cookie"
)

// TestClear_SharesBuildAttributes asserts Clear differs from Build only in
// the value and the expiry, for every predefined profile.
func TestClear_SharesBuildAttributes(t *testing.T) {
	t.Parallel()

	profiles := map[string]cookie.Profile{
		"session":     cookie.SessionProfile,
		"interaction": cookie.InteractionProfile,
		"csrf":        cookie.CSRFProfile,
		"logout_csrf": cookie.LogoutCSRFProfile,
		"locale":      cookie.LocaleProfile,
	}
	for name, p := range profiles {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			built, err := cookie.Build(p, "v")
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			cleared, err := cookie.Clear(p)
			if err != nil {
				t.Fatalf("Clear: %v", err)
			}
			if cleared.Name != built.Name || cleared.Path != built.Path || cleared.Domain != built.Domain ||
				cleared.Secure != built.Secure || cleared.HttpOnly != built.HttpOnly ||
				cleared.SameSite != built.SameSite || cleared.Partitioned != built.Partitioned {
				t.Errorf("Clear attributes %+v differ from Build %+v", cleared, built)
			}
			if cleared.Value != "" || cleared.MaxAge != -1 || !cleared.Expires.IsZero() {
				t.Errorf("Clear expiry fields = (%q, %d, %v), want (\"\", -1, zero)", cleared.Value, cleared.MaxAge, cleared.Expires)
			}
		})
	}
}
