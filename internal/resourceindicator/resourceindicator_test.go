package resourceindicator_test

import (
	"errors"
	"testing"

	"github.com/libraz/go-oidc-provider/internal/resourceindicator"
)

// TestCanonicalize_Table walks the structural rules documented on the
// package: lowercase scheme + host, default-port stripping, trailing-
// slash normalisation, fragment / userinfo rejection, query preservation,
// and the empty-input contract.
func TestCanonicalize_Table(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr error
	}{
		{
			name: "lowercase already canonical",
			raw:  "https://api.example.com/orders",
			want: "https://api.example.com/orders",
		},
		{
			name: "uppercase scheme is lowercased",
			raw:  "HTTPS://api.example.com/orders",
			want: "https://api.example.com/orders",
		},
		{
			name: "mixedcase host is lowercased",
			raw:  "https://API.Example.COM/orders",
			want: "https://api.example.com/orders",
		},
		{
			name: "trailing slash on root is stripped",
			raw:  "https://api.example.com/",
			want: "https://api.example.com",
		},
		{
			name: "no trailing slash on root is unchanged",
			raw:  "https://api.example.com",
			want: "https://api.example.com",
		},
		{
			name: "trailing slash on path is stripped",
			raw:  "https://api.example.com/orders/",
			want: "https://api.example.com/orders",
		},
		{
			name: "default https port 443 is stripped",
			raw:  "https://api.example.com:443/orders",
			want: "https://api.example.com/orders",
		},
		{
			name: "default http port 80 is stripped",
			raw:  "http://api.example.com:80/orders",
			want: "http://api.example.com/orders",
		},
		{
			name: "non-default port is preserved",
			raw:  "https://api.example.com:8443/orders",
			want: "https://api.example.com:8443/orders",
		},
		{
			name: "query is preserved verbatim",
			raw:  "https://api.example.com/orders?tenant=acme",
			want: "https://api.example.com/orders?tenant=acme",
		},
		{
			name: "query without path is preserved",
			raw:  "https://api.example.com?tenant=acme",
			want: "https://api.example.com?tenant=acme",
		},
		{
			name:    "empty value is rejected",
			raw:     "",
			wantErr: resourceindicator.ErrEmpty,
		},
		{
			name:    "fragment is rejected",
			raw:     "https://api.example.com/orders#section",
			wantErr: resourceindicator.ErrFragment,
		},
		{
			name:    "empty fragment is rejected",
			raw:     "https://api.example.com/orders#",
			wantErr: resourceindicator.ErrFragment,
		},
		{
			name:    "userinfo is rejected",
			raw:     "https://user@api.example.com/orders",
			wantErr: resourceindicator.ErrUserinfo,
		},
		//nolint:gosec // G101: test fixture asserting userinfo-with-password is REJECTED, not a credential.
		{
			name:    "userinfo with password is rejected",
			raw:     "https://user:pass@api.example.com/orders",
			wantErr: resourceindicator.ErrUserinfo,
		},
		{
			name:    "relative URI is rejected",
			raw:     "/orders",
			wantErr: resourceindicator.ErrNotAbsolute,
		},
		{
			name:    "scheme-only is rejected (no host)",
			raw:     "https://",
			wantErr: resourceindicator.ErrNotAbsolute,
		},
		{
			name:    "scheme without authority is rejected",
			raw:     "mailto:ops@example.com",
			wantErr: resourceindicator.ErrNotAbsolute,
		},
		{
			name:    "invalid percent-escape triggers parse error",
			raw:     "https://api.example.com/%ZZ",
			wantErr: resourceindicator.ErrParse,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := resourceindicator.Canonicalize(tc.raw)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err=%v want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err=%v", err)
			}
			if got != tc.want {
				t.Errorf("Canonicalize(%q)=%q want %q", tc.raw, got, tc.want)
			}
		})
	}
}

// TestCanonicalize_Idempotent confirms the canonical form is a fixed
// point of the function: feeding the output back in produces the same
// output. The property holds for every value Canonicalize successfully
// returns, by construction.
func TestCanonicalize_Idempotent(t *testing.T) {
	t.Parallel()

	inputs := []string{
		"HTTPS://API.Example.COM/orders/",
		"https://api.example.com:443/",
		"http://api.example.com:80",
		"https://api.example.com/path/sub/",
		"https://[::1]:8443/api",
	}
	for _, raw := range inputs {
		first, err := resourceindicator.Canonicalize(raw)
		if err != nil {
			t.Fatalf("Canonicalize(%q): %v", raw, err)
		}
		second, err := resourceindicator.Canonicalize(first)
		if err != nil {
			t.Fatalf("Canonicalize(%q): %v", first, err)
		}
		if first != second {
			t.Errorf("not idempotent: Canonicalize(%q)=%q then Canonicalize(%q)=%q", raw, first, first, second)
		}
	}
}

// TestValidate_Mirrors_Canonicalize confirms Validate returns the same
// error verdict as Canonicalize for every input — the helper exists only
// to discard the canonical string.
func TestValidate_Mirrors_Canonicalize(t *testing.T) {
	t.Parallel()

	cases := []string{
		"https://api.example.com/orders",
		"",
		"https://api.example.com#frag",
		"https://user@api.example.com/",
		"/relative",
	}
	for _, raw := range cases {
		_, canonErr := resourceindicator.Canonicalize(raw)
		valErr := resourceindicator.Validate(raw)
		if (canonErr == nil) != (valErr == nil) {
			t.Errorf("Validate(%q)=%v but Canonicalize=%v", raw, valErr, canonErr)
		}
	}
}

// TestEqual_Cases pins the byte-equivalence semantics: canonicalisation
// happens on both sides so the equality predicate is reflexive across
// every shape Canonicalize tolerates. Malformed input on either side
// collapses to false, never an accidental match.
func TestEqual_Cases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a    string
		b    string
		want bool
	}{
		{
			name: "identical canonical forms",
			a:    "https://api.example.com/orders",
			b:    "https://api.example.com/orders",
			want: true,
		},
		{
			name: "mixed-case host vs lowercase",
			a:    "https://API.Example.COM/orders",
			b:    "https://api.example.com/orders",
			want: true,
		},
		{
			name: "trailing slash vs none",
			a:    "https://api.example.com/orders/",
			b:    "https://api.example.com/orders",
			want: true,
		},
		{
			name: "default port vs implicit",
			a:    "https://api.example.com:443/orders",
			b:    "https://api.example.com/orders",
			want: true,
		},
		{
			name: "query order matters (RFC 8707 preserves)",
			a:    "https://api.example.com/?a=1&b=2",
			b:    "https://api.example.com/?b=2&a=1",
			want: false,
		},
		{
			name: "different host",
			a:    "https://api.example.com/orders",
			b:    "https://other.example.com/orders",
			want: false,
		},
		{
			name: "different scheme",
			a:    "http://api.example.com/orders",
			b:    "https://api.example.com/orders",
			want: false,
		},
		{
			name: "fragment side fails",
			a:    "https://api.example.com/orders#x",
			b:    "https://api.example.com/orders",
			want: false,
		},
		{
			name: "userinfo side fails",
			a:    "https://user@api.example.com/orders",
			b:    "https://api.example.com/orders",
			want: false,
		},
		{
			name: "both empty",
			a:    "",
			b:    "",
			want: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := resourceindicator.Equal(tc.a, tc.b); got != tc.want {
				t.Errorf("Equal(%q,%q)=%v want %v", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

// TestContains_HandlesMixedRegistration mirrors the realistic case: the
// allowlist may have been written before this package existed, so it can
// hold mixed-case / trailing-slash records. The helper canonicalises
// every entry on lookup so a canonical request still matches.
func TestContains_HandlesMixedRegistration(t *testing.T) {
	t.Parallel()

	registered := []string{
		"https://API.Example.COM/orders/",
		"https://other.example.com",
	}
	cases := []struct {
		raw  string
		want bool
	}{
		{raw: "https://api.example.com/orders", want: true},
		{raw: "https://api.example.com/orders/", want: true},
		{raw: "https://API.example.com/orders", want: true},
		{raw: "https://other.example.com/", want: true},
		{raw: "https://unknown.example.com/", want: false},
		{raw: "", want: false},
		{raw: "https://api.example.com/orders#frag", want: false},
	}
	for _, tc := range cases {
		if got := resourceindicator.Contains(registered, tc.raw); got != tc.want {
			t.Errorf("Contains(set, %q)=%v want %v", tc.raw, got, tc.want)
		}
	}
}

// TestContains_SkipsMalformedRegisteredEntries confirms a single
// unparseable entry in the allowlist does not stop the search; the loop
// continues to the canonical entries.
func TestContains_SkipsMalformedRegisteredEntries(t *testing.T) {
	t.Parallel()

	registered := []string{
		"https://api.example.com/orders#stale-fragment",
		"https://api.example.com/orders",
	}
	if !resourceindicator.Contains(registered, "https://api.example.com/orders") {
		t.Error("Contains skipped a valid match because of an earlier malformed entry")
	}
}

// TestCanonicalize_IPv6Literal pins the IPv6 bracketed-host handling.
// Default-port stripping must not corrupt the literal.
func TestCanonicalize_IPv6Literal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		raw  string
		want string
	}{
		{raw: "https://[::1]/api", want: "https://[::1]/api"},
		{raw: "https://[::1]:443/api", want: "https://[::1]/api"},
		{raw: "https://[::1]:8443/api", want: "https://[::1]:8443/api"},
		{raw: "http://[2001:db8::1]:80/", want: "http://[2001:db8::1]"},
	}
	for _, tc := range tests {
		got, err := resourceindicator.Canonicalize(tc.raw)
		if err != nil {
			t.Fatalf("Canonicalize(%q): %v", tc.raw, err)
		}
		if got != tc.want {
			t.Errorf("Canonicalize(%q)=%q want %q", tc.raw, got, tc.want)
		}
	}
}
