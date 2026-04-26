package csrf_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/csrf"
)

func newPOST(tb testing.TB) *http.Request {
	tb.Helper()
	return httptest.NewRequestWithContext(
		context.Background(), http.MethodPost, "https://op.example.com/x", http.NoBody,
	)
}

func TestCanonicalOrigin(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"https://app.example.com":                    "https://app.example.com",
		"https://app.example.com:443":                "https://app.example.com",
		"http://localhost:8080":                      "http://localhost:8080",
		"http://localhost:80":                        "http://localhost",
		"HTTPS://APP.EXAMPLE.COM/some/path?q=1#frag": "https://app.example.com",
	}
	for in, want := range cases {
		t.Run(in, func(t *testing.T) {
			t.Parallel()
			got, err := csrf.CanonicalOrigin(in)
			if err != nil {
				t.Fatalf("err=%v", err)
			}
			if got != want {
				t.Errorf("got %q want %q", got, want)
			}
		})
	}
}

func TestCanonicalOrigin_RejectsRelativeURLs(t *testing.T) {
	t.Parallel()

	cases := []string{"", "not a url", "/relative", "//host-only"}
	for _, in := range cases {
		if _, err := csrf.CanonicalOrigin(in); err == nil {
			t.Errorf("CanonicalOrigin(%q) err=nil want error", in)
		}
	}
}

func TestNewAllowlist_RejectsBadEntries(t *testing.T) {
	t.Parallel()

	if _, err := csrf.NewAllowlist([]string{"https://ok.example.com", "not-a-url"}); err == nil {
		t.Error("NewAllowlist accepted invalid origin")
	}
}

func TestAllowlist_Contains_AfterCanonicalisation(t *testing.T) {
	t.Parallel()

	a, err := csrf.NewAllowlist([]string{"https://app.example.com:443"})
	if err != nil {
		t.Fatalf("NewAllowlist: %v", err)
	}
	if !a.Contains("https://app.example.com") {
		t.Error("port-stripped form not contained")
	}
	if a.Contains("http://app.example.com") {
		t.Error("scheme mismatch must not match")
	}
	if a.Len() != 1 {
		t.Errorf("Len=%d want 1", a.Len())
	}
}

func TestAllowlist_Deduplicates(t *testing.T) {
	t.Parallel()

	a, err := csrf.NewAllowlist([]string{
		"https://app.example.com",
		"HTTPS://app.example.com:443/foo",
		"https://app.example.com",
	})
	if err != nil {
		t.Fatalf("NewAllowlist: %v", err)
	}
	if a.Len() != 1 {
		t.Errorf("Len=%d want 1 (canonical dedup)", a.Len())
	}
}

func TestCheckOrigin_AcceptsAllowedOrigin(t *testing.T) {
	t.Parallel()

	a, _ := csrf.NewAllowlist([]string{"https://app.example.com"})
	r := newPOST(t)
	r.Header.Set("Origin", "https://app.example.com")
	if err := csrf.CheckOrigin(r, a); err != nil {
		t.Errorf("CheckOrigin: %v", err)
	}
}

func TestCheckOrigin_RejectsForeignOrigin(t *testing.T) {
	t.Parallel()

	a, _ := csrf.NewAllowlist([]string{"https://app.example.com"})
	r := newPOST(t)
	r.Header.Set("Origin", "https://attacker.example.com")
	if err := csrf.CheckOrigin(r, a); !errors.Is(err, csrf.ErrOriginRejected) {
		t.Errorf("err=%v want ErrOriginRejected", err)
	}
}

func TestCheckOrigin_FallsBackToReferer(t *testing.T) {
	t.Parallel()

	a, _ := csrf.NewAllowlist([]string{"https://app.example.com"})
	r := newPOST(t)
	// No Origin header — UA stripped it (privacy mode, legacy browser).
	r.Header.Set("Referer", "https://app.example.com/login")
	if err := csrf.CheckOrigin(r, a); err != nil {
		t.Errorf("CheckOrigin via Referer: %v", err)
	}
}

func TestCheckOrigin_RejectsForeignReferer(t *testing.T) {
	t.Parallel()

	a, _ := csrf.NewAllowlist([]string{"https://app.example.com"})
	r := newPOST(t)
	r.Header.Set("Referer", "https://evil.example.com/")
	if err := csrf.CheckOrigin(r, a); !errors.Is(err, csrf.ErrOriginRejected) {
		t.Errorf("err=%v want ErrOriginRejected", err)
	}
}

func TestCheckOrigin_RejectsMissingBoth(t *testing.T) {
	t.Parallel()

	a, _ := csrf.NewAllowlist([]string{"https://app.example.com"})
	r := newPOST(t)
	// Neither Origin nor Referer.
	if err := csrf.CheckOrigin(r, a); !errors.Is(err, csrf.ErrOriginRejected) {
		t.Errorf("err=%v want ErrOriginRejected", err)
	}
}

func TestCheckOrigin_RejectsMalformedHeader(t *testing.T) {
	t.Parallel()

	a, _ := csrf.NewAllowlist([]string{"https://app.example.com"})
	r := newPOST(t)
	r.Header.Set("Origin", "::::not a url::::")
	if err := csrf.CheckOrigin(r, a); !errors.Is(err, csrf.ErrOriginRejected) {
		t.Errorf("err=%v want ErrOriginRejected", err)
	}
}

func TestCheckOrigin_PrefersOriginOverReferer(t *testing.T) {
	t.Parallel()

	a, _ := csrf.NewAllowlist([]string{"https://app.example.com"})
	r := newPOST(t)
	// Origin is foreign — Referer is allowed. The check must still reject
	// because Origin is the authoritative signal when present.
	r.Header.Set("Origin", "https://evil.example.com")
	r.Header.Set("Referer", "https://app.example.com/x")
	if err := csrf.CheckOrigin(r, a); !errors.Is(err, csrf.ErrOriginRejected) {
		t.Errorf("err=%v want ErrOriginRejected", err)
	}
}
