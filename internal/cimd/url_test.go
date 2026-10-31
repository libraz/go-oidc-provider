//nolint:testpackage // exercises the unexported URL rule directly.
package cimd

import (
	"strings"
	"testing"
)

func TestValidClientIDURL(t *testing.T) {
	t.Parallel()

	const prefix = "https://example.com/" // 20 bytes
	at255 := prefix + strings.Repeat("a", maxClientIDBytes-len(prefix))
	at256 := at255 + "a"

	cases := []struct {
		name      string
		id        string
		allowHTTP bool
		want      bool
	}{
		{"https with path", "https://example.com/client.json", false, true},
		{"http refused by default", "http://example.com/client.json", false, false},
		{"http admitted under dev opt-in", "http://127.0.0.1:8080/client.json", true, true},
		{"no path", "https://example.com", false, false},
		{"root path", "https://example.com/", false, false},
		{"double-dot segment", "https://example.com/a/../b", false, false},
		{"single-dot segment", "https://example.com/a/./b", false, false},
		{"trailing dot segment", "https://example.com/a/.", false, false},
		{"percent-encoded dot segment", "https://example.com/a/%2E%2e/b", false, false},
		{"fragment", "https://example.com/a#f", false, false},
		{"empty fragment", "https://example.com/a#", false, false},
		{"userinfo", "https://u@example.com/a", false, false},
		{"userinfo with password", "https://u:p@example.com/a", false, false},
		{"query", "https://example.com/a?x=1", false, false},
		{"empty query", "https://example.com/a?", false, false},
		{"upper-case host", "https://EXAMPLE.com/a", false, true},
		{"explicit port", "https://example.com:8443/a", false, true},
		{"IDN host", "https://例え.jp/a", false, false},
		{"punycode host", "https://xn--r8jz45g.jp/a", false, true},
		{"percent-encoded host", "https://ex%41mple.com/a", false, false},
		{"percent-encoded path", "https://example.com/a%20b/c", false, true},
		{"upper-case scheme", "HTTPS://example.com/a", false, false},
		{"other scheme", "ftp://example.com/a", false, false},
		{"empty authority", "https:///a", false, false},
		{"port without host", "https://:443/a", false, false},
		{"empty", "", false, false},
		{"plain client id", "rp-1", false, false},
		{"255 bytes", at255, false, true},
		{"256 bytes", at256, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := validClientIDURL(tc.id, tc.allowHTTP); got != tc.want {
				t.Fatalf("validClientIDURL(%q, %v) = %v, want %v", tc.id, tc.allowHTTP, got, tc.want)
			}
		})
	}
}
