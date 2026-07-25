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
		// A literal IPv6 host keeps its brackets: without them the
		// address colons and the port separator run together, producing
		// a string no browser would ever send as an Origin.
		"http://[::1]:8080": "http://[::1]:8080",
		"http://[::1]:80":   "http://[::1]",
		"https://[::1]":     "https://[::1]",
		"https://[FE80::1]": "https://[fe80::1]",
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

func TestCanonicalOrigin_RejectsHardeningCases(t *testing.T) {
	t.Parallel()

	//nolint:gosec // test fixtures; the userinfo-bearing URLs are the rejection targets.
	cases := map[string]string{
		"userinfo":      "https://user:pass@trusted.example",
		"userinfo_only": "https://user@trusted.example",
		// Note: `https://evil.example/?@trusted.example` is NOT in this
		// rejection set because url.Parse correctly resolves its host to
		// `evil.example` with the rest treated as a query. The follow-up
		// test TestCanonicalOrigin_UserinfoAtObfuscationDoesNotPromoteToTrusted
		// pins that the canonicalization stays on evil.example.
		"javascript_scheme": "javascript:alert(1)",
		"data_scheme":       "data:text/html,<script>",
		"file_scheme":       "file:///etc/passwd",
		"ftp_scheme":        "ftp://trusted.example",
		"ws_scheme":         "ws://trusted.example",
		"opaque_mailto":     "mailto:admin@trusted.example",
	}
	for name, in := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			canon, err := csrf.CanonicalOrigin(in)
			if err == nil {
				t.Errorf("CanonicalOrigin(%q) accepted hostile input as %q", in, canon)
			}
		})
	}
}

func TestCanonicalOrigin_UserinfoAtObfuscationDoesNotPromoteToTrusted(t *testing.T) {
	t.Parallel()

	// Concrete regression: `https://evil.example/?@trusted.example` is a
	// query-only URL whose host is `evil.example`. Even if a downstream
	// parser misread the userinfo, the result must NOT canonicalise to
	// `https://trusted.example`.
	got, err := csrf.CanonicalOrigin("https://evil.example/?@trusted.example")
	if err == nil && got == "https://trusted.example" {
		t.Errorf("evil URL canonicalised to trusted origin: %q", got)
	}
}

func TestCheckOrigin_RejectsUserinfoOrigin(t *testing.T) {
	t.Parallel()

	a, _ := csrf.NewAllowlist([]string{"https://app.example.com"})
	r := newPOST(t)
	r.Header.Set("Origin", "https://attacker:pwn@app.example.com")
	if err := csrf.CheckOrigin(r, a); !errors.Is(err, csrf.ErrOriginRejected) {
		t.Errorf("err=%v want ErrOriginRejected (userinfo in Origin)", err)
	}
}

func TestCheckOrigin_RejectsForeignSchemeOrigin(t *testing.T) {
	t.Parallel()

	a, _ := csrf.NewAllowlist([]string{"https://app.example.com"})
	r := newPOST(t)
	r.Header.Set("Origin", "javascript:alert(1)")
	if err := csrf.CheckOrigin(r, a); !errors.Is(err, csrf.ErrOriginRejected) {
		t.Errorf("err=%v want ErrOriginRejected (non-http(s) Origin)", err)
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
	// Sec-Fetch-Site: same-origin vouches the fetch originated from the
	// OP's own pages; without it the Referer-only path is rejected.
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	if err := csrf.CheckOrigin(r, a); err != nil {
		t.Errorf("CheckOrigin via Referer: %v", err)
	}
}

func TestCheckOrigin_RejectsForeignReferer(t *testing.T) {
	t.Parallel()

	a, _ := csrf.NewAllowlist([]string{"https://app.example.com"})
	r := newPOST(t)
	r.Header.Set("Referer", "https://evil.example.com/")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	if err := csrf.CheckOrigin(r, a); !errors.Is(err, csrf.ErrOriginRejected) {
		t.Errorf("err=%v want ErrOriginRejected", err)
	}
}

// TestCheckOrigin_RejectsRefererWithoutFetchMetadata pins the H-C2
// hardening: a request that supplies Referer alone — no Origin header,
// no Sec-Fetch-Site — is rejected. Modern browsers emit Origin on every
// state-changing fetch, so the Referer-only path is the legacy
// fallback; admitting it without a Fetch Metadata vouch lets a privacy
// mode / extension that strips Origin AND emits no Sec-Fetch-Site (a
// rare combination on contemporary UAs but reachable through hostile
// configurations) reach the CSRF gate without forging any header.
func TestCheckOrigin_RejectsRefererWithoutFetchMetadata(t *testing.T) {
	t.Parallel()

	a, _ := csrf.NewAllowlist([]string{"https://app.example.com"})
	r := newPOST(t)
	// Allowlisted Referer but no Sec-Fetch-Site — gate must still reject.
	r.Header.Set("Referer", "https://app.example.com/login")
	if err := csrf.CheckOrigin(r, a); !errors.Is(err, csrf.ErrOriginRejected) {
		t.Errorf("err=%v want ErrOriginRejected (no Sec-Fetch-Site)", err)
	}
}

// TestCheckOrigin_RejectsRefererWithCrossSiteFetchMetadata pins that a
// non-same-origin Sec-Fetch-Site value (cross-site, same-site, none)
// fails the gate even when Referer matches. The Referer fallback is
// reserved for fetches the browser itself classifies as same-origin.
func TestCheckOrigin_RejectsRefererWithCrossSiteFetchMetadata(t *testing.T) {
	t.Parallel()

	a, _ := csrf.NewAllowlist([]string{"https://app.example.com"})
	for _, site := range []string{"cross-site", "same-site", "none"} {
		r := newPOST(t)
		r.Header.Set("Referer", "https://app.example.com/login")
		r.Header.Set("Sec-Fetch-Site", site)
		if err := csrf.CheckOrigin(r, a); !errors.Is(err, csrf.ErrOriginRejected) {
			t.Errorf("Sec-Fetch-Site=%q: err=%v want ErrOriginRejected", site, err)
		}
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
