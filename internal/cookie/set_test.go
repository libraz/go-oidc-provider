package cookie_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/cookie"
)

func TestSet_RejectsMissingHostPrefix(t *testing.T) {
	t.Parallel()

	cases := []string{"oidc_session", "Host-oidc_session", "__host-oidc"}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			rec := httptest.NewRecorder()
			err := cookie.Set(rec, name, "v", cookie.SetOptions{})
			if !errors.Is(err, cookie.ErrMissingHostPrefix) {
				t.Errorf("err=%v want ErrMissingHostPrefix", err)
			}
			if got := rec.Header().Get("Set-Cookie"); got != "" {
				t.Errorf("Set-Cookie emitted on rejection: %q", got)
			}
		})
	}
}

func TestSet_StampsMandatoryAttributes(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	if err := cookie.Set(rec, "__Host-oidc_session", "abc", cookie.SetOptions{
		MaxAge: 3600,
	}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got := rec.Header().Get("Set-Cookie")
	if got == "" {
		t.Fatal("Set-Cookie missing")
	}
	required := []string{
		"__Host-oidc_session=abc",
		"Path=/",
		"HttpOnly",
		"Secure",
		"SameSite=Lax",
		"Max-Age=3600",
	}
	for _, want := range required {
		if !strings.Contains(got, want) {
			t.Errorf("Set-Cookie %q missing %q", got, want)
		}
	}
	if strings.Contains(got, "Domain=") {
		t.Errorf("Set-Cookie %q must not carry Domain attribute", got)
	}
}

func TestSet_HonoursSameSiteOverride(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	if err := cookie.Set(rec, "__Host-oidc_csrf", "tok", cookie.SetOptions{
		SameSite: http.SameSiteStrictMode,
	}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if got := rec.Header().Get("Set-Cookie"); !strings.Contains(got, "SameSite=Strict") {
		t.Errorf("Set-Cookie %q missing SameSite=Strict", got)
	}
}

func TestSet_NegativeMaxAgeDeletes(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	if err := cookie.Set(rec, "__Host-oidc_session", "", cookie.SetOptions{MaxAge: -1}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got := rec.Header().Get("Set-Cookie")
	if !strings.Contains(got, "Max-Age=0") {
		t.Errorf("Set-Cookie %q must encode deletion (Max-Age=0)", got)
	}
}

func TestClear_DelegatesToSet(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	if err := cookie.ClearByName(rec, "__Host-oidc_session"); err != nil {
		t.Fatalf("ClearByName: %v", err)
	}
	got := rec.Header().Get("Set-Cookie")
	if !strings.Contains(got, "__Host-oidc_session=") {
		t.Errorf("Set-Cookie %q must reference the deleted name", got)
	}
	if !strings.Contains(got, "HttpOnly") || !strings.Contains(got, "Secure") {
		t.Errorf("Clear must keep mandatory attributes: %q", got)
	}
}

func TestClear_RejectsMissingPrefix(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	if err := cookie.ClearByName(rec, "session"); !errors.Is(err, cookie.ErrMissingHostPrefix) {
		t.Errorf("err=%v want ErrMissingHostPrefix", err)
	}
}
