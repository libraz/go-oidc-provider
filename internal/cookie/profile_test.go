package cookie_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/libraz/go-oidc-provider/internal/cookie"
)

func TestPredefinedProfiles_BuildSuccessfully(t *testing.T) {
	t.Parallel()

	cases := map[string]cookie.Profile{
		"session":     cookie.SessionProfile,
		"interaction": cookie.InteractionProfile,
		"csrf":        cookie.CSRFProfile,
		"locale":      cookie.LocaleProfile,
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c, err := cookie.Build(p, "value")
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			if c.Path != "/" {
				t.Errorf("Path=%q want /", c.Path)
			}
			if !c.Secure {
				t.Error("Secure must be true on every __Host- cookie")
			}
			if !c.HttpOnly {
				t.Error("HttpOnly must be true on every cookie")
			}
		})
	}
}

func TestSessionProfile_Defaults(t *testing.T) {
	t.Parallel()

	if cookie.SessionProfile.Name != "__Host-oidc_session" {
		t.Errorf("name=%q", cookie.SessionProfile.Name)
	}
	if cookie.SessionProfile.MaxAge != 14*24*time.Hour {
		t.Errorf("MaxAge=%v want 14d", cookie.SessionProfile.MaxAge)
	}
	if cookie.SessionProfile.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite=%v want Lax", cookie.SessionProfile.SameSite)
	}
	if !cookie.SessionProfile.Encrypted {
		t.Error("session cookie must be encrypted")
	}
}

func TestCSRFProfile_StrictAndPlaintext(t *testing.T) {
	t.Parallel()

	if cookie.CSRFProfile.SameSite != http.SameSiteStrictMode {
		t.Errorf("SameSite=%v want Strict", cookie.CSRFProfile.SameSite)
	}
	if cookie.CSRFProfile.Encrypted {
		t.Error("CSRF cookie carries an HMAC token, must not be encrypted")
	}
	if cookie.CSRFProfile.MaxAge != 0 {
		t.Errorf("MaxAge=%v want 0 (session)", cookie.CSRFProfile.MaxAge)
	}
}

func TestBuild_RejectsHostPrefixMismatch(t *testing.T) {
	t.Parallel()

	cases := map[string]cookie.Profile{
		"flag_set_no_prefix": {
			Name:       "oidc_session", // missing __Host-
			SameSite:   http.SameSiteLaxMode,
			HostPrefix: true,
		},
		"prefix_no_flag": {
			Name:       "__Host-oidc_session",
			SameSite:   http.SameSiteLaxMode,
			HostPrefix: false,
		},
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := cookie.Build(p, "v"); err == nil {
				t.Error("Build returned nil error for invalid profile")
			}
		})
	}
}

func TestBuild_RequiresExplicitSameSite(t *testing.T) {
	t.Parallel()

	p := cookie.Profile{
		Name:       "__Host-x",
		HostPrefix: true,
		// SameSite zero -> SameSiteDefaultMode
	}
	if _, err := cookie.Build(p, "v"); err == nil {
		t.Error("Build accepted SameSiteDefaultMode")
	}
}

func TestBuild_RejectsEmptyName(t *testing.T) {
	t.Parallel()

	p := cookie.Profile{SameSite: http.SameSiteLaxMode}
	if _, err := cookie.Build(p, "v"); err == nil {
		t.Error("Build accepted empty name")
	}
}

func TestBuild_RejectsNegativeMaxAge(t *testing.T) {
	t.Parallel()

	p := cookie.Profile{
		Name:       "__Host-x",
		HostPrefix: true,
		SameSite:   http.SameSiteLaxMode,
		MaxAge:     -1 * time.Second,
	}
	if _, err := cookie.Build(p, "v"); err == nil {
		t.Error("Build accepted negative MaxAge (reserved for Clear)")
	}
}

func TestBuild_MaxAgeSecondsRounded(t *testing.T) {
	t.Parallel()

	c, err := cookie.Build(cookie.SessionProfile, "v")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	want := int((14 * 24 * time.Hour).Seconds())
	if c.MaxAge != want {
		t.Errorf("MaxAge=%d want %d", c.MaxAge, want)
	}
}

func TestBuild_SessionCookieHasZeroMaxAge(t *testing.T) {
	t.Parallel()

	c, err := cookie.Build(cookie.CSRFProfile, "v")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if c.MaxAge != 0 {
		t.Errorf("MaxAge=%d want 0 (session cookie)", c.MaxAge)
	}
}

func TestBuild_RejectsSameSiteNoneWithInsecure(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		profile cookie.Profile
		wantErr bool
	}{
		"none_insecure_rejected": {
			profile: cookie.Profile{
				Name:       "__Host-x",
				HostPrefix: true,
				SameSite:   http.SameSiteNoneMode,
				Insecure:   true,
			},
			wantErr: true,
		},
		"none_secure_accepted": {
			profile: cookie.Profile{
				Name:       "__Host-x",
				HostPrefix: true,
				SameSite:   http.SameSiteNoneMode,
				Insecure:   false,
			},
			wantErr: false,
		},
		"lax_insecure_accepted": {
			// Lax + Insecure is structurally permitted (e.g. dev origin
			// over plain HTTP); only SameSite=None gates Insecure per
			// RFC 6265bis §4.1.2.7.
			profile: cookie.Profile{
				Name:       "x",
				HostPrefix: false,
				SameSite:   http.SameSiteLaxMode,
				Insecure:   true,
			},
			wantErr: false,
		},
		"strict_insecure_accepted": {
			profile: cookie.Profile{
				Name:       "x",
				HostPrefix: false,
				SameSite:   http.SameSiteStrictMode,
				Insecure:   true,
			},
			wantErr: false,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			c, err := cookie.Build(tc.profile, "v")
			switch {
			case tc.wantErr && err == nil:
				t.Errorf("Build accepted SameSite=None+Insecure profile: %+v", c)
			case !tc.wantErr && err != nil:
				t.Errorf("Build rejected valid profile: %v", err)
			}
		})
	}
}

func TestBuild_InsecureSetsSecureFalse(t *testing.T) {
	t.Parallel()

	p := cookie.Profile{
		Name:       "dev_session",
		SameSite:   http.SameSiteLaxMode,
		HostPrefix: false,
		Insecure:   true,
	}
	c, err := cookie.Build(p, "v")
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if c.Secure {
		t.Error("Build did not honour Insecure=true: Secure=true")
	}
}

func TestClear_RejectsSameSiteNoneWithInsecure(t *testing.T) {
	t.Parallel()

	p := cookie.Profile{
		Name:       "__Host-x",
		HostPrefix: true,
		SameSite:   http.SameSiteNoneMode,
		Insecure:   true,
	}
	if _, err := cookie.Clear(p); err == nil {
		t.Error("Clear accepted SameSite=None+Insecure profile")
	}
}

func TestClear_EmitsExpiringCookie(t *testing.T) {
	t.Parallel()

	c, err := cookie.Clear(cookie.SessionProfile)
	if err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if c.Value != "" {
		t.Errorf("Value=%q want empty", c.Value)
	}
	if c.MaxAge != -1 {
		t.Errorf("MaxAge=%d want -1", c.MaxAge)
	}
	if !c.Secure || !c.HttpOnly || c.Path != "/" {
		t.Errorf("attrs=%+v want Secure+HttpOnly+Path=/", c)
	}
}
