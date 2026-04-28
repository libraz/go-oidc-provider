// White-box table for [canonicalEqual]. RFC 9449 §4.3 makes the htu
// match a structural pre-condition for binding the proof to the
// resource request, so the table here pins every variant the
// canonicaliser is expected to fold or preserve. A regression that
// over-folds (treats "/Path" == "/path") would let an attacker reuse
// a proof minted for one endpoint at another; a regression that
// under-folds (rejects ":443" vs "") would break legitimate clients
// behind common reverse proxies.
//
// Tracks: RFC 9449 §4.3 (htu canonicalisation), RFC 3986 §6.2.2 / §6.2.3
// (URI normalisation rules), and the FAPI 2.0 formal analysis
// (eprint.iacr.org/2024/1540) which lists "DPoP proof reuse across
// endpoints" as a regression class to defend against. Note that no
// single CVE is assigned to this attack — it is a structural variant
// of the broader DPoP proof-replay surface.
//
//nolint:testpackage // white-box: canonicalEqual is unexported.
package dpop

import "testing"

func TestCanonicalEqual_Table(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		htu  string
		req  string
		want bool
	}{
		// --- byte-equal --------------------------------------------------
		{"identical", "https://op.example/oidc/token", "https://op.example/oidc/token", true},

		// --- query / fragment stripped on both sides ---------------------
		{"htu_has_query", "https://op.example/oidc/token?x=1", "https://op.example/oidc/token", true},
		{"req_has_query", "https://op.example/oidc/token", "https://op.example/oidc/token?x=1", true},
		{"both_have_query", "https://op.example/oidc/token?a=1", "https://op.example/oidc/token?b=2", true},
		{"htu_has_fragment", "https://op.example/oidc/token#part", "https://op.example/oidc/token", true},
		{"req_has_fragment", "https://op.example/oidc/token", "https://op.example/oidc/token#part", true},

		// --- case folding: scheme & host folded, path NOT folded ---------
		{"scheme_uppercase", "HTTPS://op.example/oidc/token", "https://op.example/oidc/token", true},
		{"scheme_mixed", "Https://op.example/oidc/token", "https://op.example/oidc/token", true},
		{"host_uppercase", "https://OP.EXAMPLE/oidc/token", "https://op.example/oidc/token", true},
		{"host_mixed", "https://Op.Example/oidc/token", "https://op.example/oidc/token", true},
		// Path is case-sensitive per RFC 3986 §6.2.2.1.
		{"path_uppercase_distinct", "https://op.example/oidc/Token", "https://op.example/oidc/token", false},
		{"path_mixed_distinct", "https://op.example/OIDC/token", "https://op.example/oidc/token", false},

		// --- trailing slash IS significant (RFC 3986 §6.2.2.3) -----------
		{"trailing_slash_distinct", "https://op.example/oidc/token/", "https://op.example/oidc/token", false},
		{"trailing_slash_root_only", "https://op.example/", "https://op.example", false},

		// --- different paths -> no match ---------------------------------
		{"different_path", "https://op.example/oidc/par", "https://op.example/oidc/token", false},
		{"sibling_path", "https://op.example/oidc/userinfo", "https://op.example/oidc/token", false},

		// --- different host / scheme -> no match -------------------------
		{"http_vs_https", "http://op.example/oidc/token", "https://op.example/oidc/token", false},
		{"different_host", "https://attacker.example/oidc/token", "https://op.example/oidc/token", false},

		// --- userinfo present in URL: distinct from no userinfo ----------
		// RFC 3986 §3.2.1 makes userinfo a distinct component; net/url
		// preserves it through String() so canonicalEqual sees them
		// differ. A proof carrying userinfo MUST NOT match a request
		// without it.
		{"userinfo_distinct", "https://alice@op.example/oidc/token", "https://op.example/oidc/token", false},

		// --- unparseable inputs -> no match ------------------------------
		// canonicalEqual is byte-equal-first, so two byte-equal garbage
		// strings still match. Distinct garbage doesn't.
		{"both_garbage_equal", "::not-a-url::", "::not-a-url::", true},
		{"distinct_garbage", "::not-a-url-A::", "::not-a-url-B::", false},

		// --- empty -------------------------------------------------------
		{"both_empty", "", "", true},
		{"htu_empty", "", "https://op.example/oidc/token", false},
		{"req_empty", "https://op.example/oidc/token", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := canonicalEqual(tc.htu, tc.req); got != tc.want {
				t.Fatalf("canonicalEqual(%q, %q) = %v, want %v", tc.htu, tc.req, got, tc.want)
			}
		})
	}
}
